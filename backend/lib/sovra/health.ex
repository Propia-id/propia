defmodule Sovra.Health do
  @moduledoc """
  Readiness of an API node: can this process actually serve a request?

  Polls every dependency on a jittered interval and keeps the latest verdict in
  ETS; `SovraWeb.HealthController.ready/2` reads that table and does no I/O of
  its own. That is the whole point of the design — `/ready` is unauthenticated
  and externally reachable, so a request must never be able to reach a
  dependency, and a wedged poll must never be able to wedge the endpoint.

  `init/1` does no I/O, so a dead dependency cannot fail boot. The first poll
  runs from `handle_continue/2`, which is after `start_link/1` has returned, so
  it does not hold up the rest of the supervision tree either. Until it lands
  the snapshot reads `:starting`.

  Each cycle emits telemetry that `Sovra.PromEx.HealthPlugin` turns into gauges,
  so the same verdict drives both the probe and the alerts.

  A check reports `:ok`, `{:error, reason}`, or `:skipped` — the last meaning
  the dependency does not exist on this configuration (there is no signer
  service behind the software key store), which counts as healthy because there
  is nothing to be down.
  """

  use GenServer
  use Sovra.Log

  alias Ecto.Adapters.SQL
  alias Sovra.Ethereum.{Chains, ChainIdProbe}
  alias Sovra.Repo
  alias Sovra.Signer.Probe

  @table __MODULE__
  @check_event [:sovra, :health, :check]
  @cycle_event [:sovra, :health, :cycle]

  @default_interval_ms :timer.minutes(1)
  @default_check_timeout_ms 5_000
  # Well under the check timeout: a saturated pool must be *detected*, not
  # waited on, and a checkout that outlives the killed task keeps holding a slot.
  @default_db_timeout_ms 2_000

  @type snapshot :: %{
          status: :ok | :error | :starting,
          checked_at: DateTime.t() | nil,
          checks: %{atom() => term()}
        }

  @doc false
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  The latest verdict, or `:unavailable` when the monitor is not running (disabled
  by config, or dead between restarts — the ETS table dies with its owner).
  """
  @spec snapshot() :: snapshot() | :unavailable
  def snapshot do
    case :ets.whereis(@table) do
      :undefined -> :unavailable
      tid -> read(tid)
    end
  end

  @doc """
  Runs one cycle synchronously and returns the snapshot it stored. For tests;
  `timeout` must exceed `:check_timeout_ms`.
  """
  @spec check_now(timeout()) :: snapshot()
  def check_now(timeout \\ 30_000), do: GenServer.call(__MODULE__, :check, timeout)

  @impl true
  def init(opts) do
    config = Keyword.merge(Application.get_env(:sovra, __MODULE__, []), opts)

    if Keyword.get(config, :enabled, true) do
      state = %{
        interval_ms: Keyword.get(config, :interval_ms, @default_interval_ms),
        check_timeout_ms: Keyword.get(config, :check_timeout_ms, @default_check_timeout_ms),
        db_timeout_ms: Keyword.get(config, :db_timeout_ms, @default_db_timeout_ms)
      }

      # Created before the first poll so the controller always finds a table and
      # reads `:starting` rather than `:unavailable`.
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
      :ets.insert(@table, {:snapshot, starting_snapshot()})

      {:ok, state, {:continue, :first_check}}
    else
      :ignore
    end
  end

  @impl true
  def handle_continue(:first_check, state) do
    _ = run(state)
    Process.send_after(self(), :check, next_delay(state.interval_ms))
    {:noreply, state}
  end

  @impl true
  def handle_info(:check, state) do
    _ = run(state)
    Process.send_after(self(), :check, next_delay(state.interval_ms))
    {:noreply, state}
  end

  @impl true
  def handle_call(:check, _from, state), do: {:reply, run(state), state}

  # ±10% so nodes restarted together do not keep polling a shared RPC endpoint
  # in lockstep.
  defp next_delay(interval_ms) do
    spread = max(div(interval_ms, 5), 1)
    interval_ms - div(spread, 2) + :rand.uniform(spread)
  end

  # --- the cycle --------------------------------------------------------------

  defp run(state) do
    checks = checks(state)

    results =
      checks
      |> Task.async_stream(
        fn {key, fun} -> {key, timed(fun)} end,
        # A bounded timeout, not `:infinity`: ethereumex has no receive timeout
        # configured, so one unresponsive endpoint would otherwise hang the cycle.
        max_concurrency: max(length(checks), 1),
        timeout: state.check_timeout_ms,
        on_timeout: :kill_task,
        zip_input_on_exit: true,
        ordered: false
      )
      |> Enum.map(&collect(&1, state))

    snapshot = build_snapshot(results)
    :ets.insert(@table, {:snapshot, snapshot})
    emit(results, snapshot)
    snapshot
  end

  defp checks(state) do
    [
      {:database, fn -> check_database(state.db_timeout_ms) end},
      {:signer, &check_signer/0},
      {:signer_kms, &check_signer_kms/0}
    ] ++
      Enum.map(Chains.all(), fn {chain_id, chain} ->
        {{:rpc, chain_id, chain.name}, fn -> check_rpc(chain_id, chain.rpc_url) end}
      end)
  end

  defp timed(fun) do
    started = System.monotonic_time(:millisecond)
    result = safe(fun)
    {result, System.monotonic_time(:millisecond) - started}
  end

  # Tasks are linked here, so an unexpected raise would take the monitor down.
  defp safe(fun) do
    fun.()
  rescue
    error -> {:error, {:exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp collect({:ok, {key, {result, duration_ms}}}, _state), do: {key, result, duration_ms}

  # `zip_input_on_exit: true` hands the input back, so we know which check died.
  # The reason is kept rather than assumed to be `:timeout`: `on_timeout:
  # :kill_task` produces that one, but a task can also exit on its own.
  defp collect({:exit, {{key, _fun}, reason}}, state),
    do: {key, {:error, reason}, state.check_timeout_ms}

  # --- the individual checks --------------------------------------------------

  # Not `SELECT 1`: an API node reaches Postgres through its own HAProxy, which
  # is supposed to route to the primary. `SELECT 1` also succeeds on a standby,
  # where every write fails — so assert the thing that actually matters.
  defp check_database(timeout_ms) do
    case SQL.query(Repo, "SELECT pg_is_in_recovery()", [], timeout: timeout_ms) do
      {:ok, %{rows: [[false]]}} -> :ok
      {:ok, %{rows: [[true]]}} -> {:error, :db_standby}
      {:ok, other} -> {:error, {:unexpected_db_response, other}}
      {:error, reason} -> {:error, reason}
    end
  end

  # The authenticated path, so a rotated or mismatched SIGNER_TOKEN is caught.
  # Deliberately not `Relayer.cached_address/0`, whose memo is 24 hours.
  defp check_signer, do: Probe.relayer_address()

  # Separate from `check_signer/0` because the relayer public key is memoized on
  # the signer and stops reaching AWS after the first call: a revoked IAM role
  # or a KMS outage would stay invisible until a real signature.
  defp check_signer_kms do
    case Probe.health() do
      {:ok, %{kms: :ok}} -> :ok
      {:ok, %{kms: :skipped}} -> :skipped
      {:ok, %{kms: status}} -> {:error, {:signer_kms, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  # `eth_chainId` is reachability and correctness in one call: an endpoint that
  # answers for the wrong chain is worse than one that does not answer.
  defp check_rpc(_chain_id, url) when not is_binary(url) or url == "",
    do: {:error, :chain_rpc_not_configured}

  defp check_rpc(chain_id, url) do
    case ChainIdProbe.fetch(url) do
      {:ok, ^chain_id} -> :ok
      {:ok, _other} -> {:error, :chain_id_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  # --- snapshot + reporting ---------------------------------------------------

  defp starting_snapshot, do: %{status: :starting, checked_at: nil, checks: %{}}

  defp build_snapshot(results) do
    checks =
      Enum.reduce(results, %{}, fn {key, result, duration_ms}, acc ->
        put_check(acc, key, entry(key, result, duration_ms))
      end)

    status =
      if Enum.all?(results, fn {_key, result, _ms} -> up?(result) end), do: :ok, else: :error

    %{status: status, checked_at: DateTime.utc_now(), checks: checks}
  end

  defp put_check(acc, {:rpc, chain_id, _name}, entry) do
    Map.update(acc, :rpc, %{chain_id => entry}, &Map.put(&1, chain_id, entry))
  end

  defp put_check(acc, key, entry), do: Map.put(acc, key, entry)

  defp entry({:rpc, _chain_id, chain_name}, result, duration_ms),
    do: Map.merge(entry(nil, result, duration_ms), %{chain_name: chain_name})

  defp entry(_key, :ok, duration_ms), do: %{status: :ok, took_ms: duration_ms}
  defp entry(_key, :skipped, duration_ms), do: %{status: :skipped, took_ms: duration_ms}

  defp entry(_key, {:error, reason}, duration_ms),
    do: %{status: :error, took_ms: duration_ms, error: label(reason)}

  defp up?(:ok), do: true
  defp up?(:skipped), do: true
  defp up?({:error, _reason}), do: false

  @doc """
  Maps a raw reason onto the closed set of labels the probe and the metrics are
  allowed to expose. `/ready` is unauthenticated and externally reachable, so no
  reason term ever reaches the response body — the raw one goes to the log.
  """
  @spec label(term()) :: atom()
  def label(:timeout), do: :timeout
  def label(:db_standby), do: :db_standby
  def label(:chain_id_mismatch), do: :chain_id_mismatch
  def label(:chain_id_unreachable), do: :unreachable
  def label(:invalid_chain_id), do: :rpc_error
  def label(:chain_rpc_not_configured), do: :unconfigured
  def label(:signer_url_missing), do: :unconfigured
  def label(:signer_token_missing), do: :unconfigured
  def label(:relayer_key_not_configured), do: :unconfigured
  def label({:signer_unreachable, _reason}), do: :unreachable
  def label({:signer_error, 401, _body}), do: :auth_error
  def label({:signer_error, _status, _body}), do: :error
  def label({:signer_kms, _status}), do: :error
  def label({:unexpected_signer_response, _body}), do: :error
  def label(%DBConnection.ConnectionError{}), do: :db_error
  def label(%Postgrex.Error{}), do: :db_error
  def label({:unexpected_db_response, _row}), do: :db_error
  def label(_reason), do: :error

  defp emit(results, snapshot) do
    Enum.each(results, fn {key, result, duration_ms} ->
      {dependency, chain_id, chain_name} = tags(key)

      :telemetry.execute(
        @check_event,
        %{up: if(up?(result), do: 1, else: 0), duration_ms: duration_ms},
        %{dependency: dependency, chain_id: chain_id, chain_name: chain_name}
      )

      log(dependency, chain_id, result, duration_ms)
    end)

    :telemetry.execute(
      @cycle_event,
      %{
        ready: if(snapshot.status == :ok, do: 1, else: 0),
        timestamp_seconds: System.system_time(:second)
      },
      %{}
    )
  end

  # Empty strings rather than a second metric name: Prometheus treats an empty
  # label as absent, so one `sovra_health_dependency_up` covers every dependency.
  defp tags({:rpc, chain_id, chain_name}), do: {"rpc", to_string(chain_id), chain_name}
  defp tags(key), do: {to_string(key), "", ""}

  # `:warning`, not `:error`: a dependency that stays down would otherwise emit
  # an error line per node per cycle, forever, turning one unreachable RPC
  # endpoint into a permanent error stream. This mirrors how
  # `Sovra.Ethereum.Relayer.BalanceMonitor` logs the same class of event. The
  # `event` name is the alerting contract; the level is not.
  defp log(_dependency, _chain_id, result, _duration_ms) when result in [:ok, :skipped], do: :ok

  defp log(dependency, chain_id, {:error, reason}, duration_ms) do
    Log.event(:warning, "health check failed",
      event: "health.check.failed",
      dependency: dependency,
      # `Sovra.Log` drops empty values, so `chain_id=` never appears on the
      # non-chain dependencies even though the metric tag is always present.
      chain_id: chain_id,
      duration_ms: duration_ms,
      reason: Log.reason(reason)
    )
  end

  defp read(tid) do
    case :ets.lookup(tid, :snapshot) do
      [{:snapshot, snapshot}] -> snapshot
      [] -> starting_snapshot()
    end
  rescue
    ArgumentError -> :unavailable
  end
end
