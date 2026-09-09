defmodule Sovra.Signer.Health do
  @moduledoc """
  Is KMS actually reachable from this signer?

  The signer's liveness was already covered by systemd unit state; what was not
  covered is the state that matters — the process is up but its one dependency
  is not. There is no outbox and `Sovra.Signer.Client` does not retry, so that
  state fails every credential signature, every workspace key creation and
  every on-chain write synchronously.

  Probes on an interval and caches the verdict, rather than probing on request.
  `GET /ready` is unauthenticated by design, so a probe-on-request endpoint
  would hand anyone on the tailnet a lever on our AWS bill and our KMS rate
  limit. The probe calls `GetPublicKey` on the relayer key straight through
  `Sovra.Signer.Kms.backend/0`, deliberately bypassing the `:persistent_term`
  memo in `Sovra.Signer.Relayer` — a cached read would keep answering long
  after the IAM role was revoked.

  `init/1` does no I/O, so KMS being down cannot stop the signer from booting
  and serving its own verdict.
  """

  use GenServer

  alias Sovra.Signer.{Kms, Relayer}

  require Logger

  @table __MODULE__
  @default_interval_ms :timer.minutes(1)

  @typedoc "`:unavailable` means this monitor is not running, not that KMS is down."
  @type status :: :ok | :error | :starting | :unavailable

  @typedoc "The verdict plus when it was taken; `checked_at` is nil before the first probe."
  @type snapshot :: %{status: status(), checked_at: DateTime.t() | nil}

  @doc false
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "The cached KMS verdict. Never performs I/O."
  @spec status() :: status()
  def status do
    case snapshot() do
      :unavailable -> :unavailable
      %{status: status} -> status
    end
  end

  @doc """
  The cached verdict with the time it was taken, or `:unavailable` when the
  monitor is not running. Never performs I/O; `GET /ready` renders this.
  """
  @spec snapshot() :: snapshot() | :unavailable
  def snapshot do
    case :ets.whereis(@table) do
      :undefined -> :unavailable
      tid -> read(tid)
    end
  end

  @doc "Runs one probe synchronously and returns the stored status. For tests."
  @spec check_now(timeout()) :: status()
  def check_now(timeout \\ 30_000), do: GenServer.call(__MODULE__, :check, timeout)

  @impl true
  def init(opts) do
    config = Keyword.merge(Application.get_env(:sovra, __MODULE__, []), opts)

    if Keyword.get(config, :enabled, true) do
      state = %{interval_ms: Keyword.get(config, :interval_ms, @default_interval_ms)}

      # Created before the first probe so the router always finds a table and
      # reads `starting` rather than `unavailable`.
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
      :ets.insert(@table, {:snapshot, %{status: :starting, checked_at: nil}})

      {:ok, state, {:continue, :first_check}}
    else
      :ignore
    end
  end

  @impl true
  def handle_continue(:first_check, state) do
    _ = probe()
    Process.send_after(self(), :check, next_delay(state.interval_ms))
    {:noreply, state}
  end

  @impl true
  def handle_info(:check, state) do
    _ = probe()
    Process.send_after(self(), :check, next_delay(state.interval_ms))
    {:noreply, state}
  end

  @impl true
  def handle_call(:check, _from, state), do: {:reply, probe(), state}

  # ±10% so signers restarted together do not hit KMS in lockstep.
  defp next_delay(interval_ms) do
    spread = max(div(interval_ms, 5), 1)
    interval_ms - div(spread, 2) + :rand.uniform(spread)
  end

  defp probe do
    status =
      case read_relayer_key() do
        {:ok, _der} ->
          :ok

        {:error, reason} ->
          # The reason stays here. It names a KMS key id or an AWS failure, and
          # the endpoint that reports this status is unauthenticated.
          Logger.warning("signer.kms_unhealthy err=#{inspect(reason)}")
          :error
      end

    :ets.insert(@table, {:snapshot, %{status: status, checked_at: DateTime.utc_now()}})
    status
  end

  defp read_relayer_key do
    with {:ok, key_id} <- Relayer.key_id() do
      Kms.backend().get_public_key(key_id)
    end
  rescue
    error -> {:error, {:exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp read(tid) do
    case :ets.lookup(tid, :snapshot) do
      [{:snapshot, snapshot}] -> snapshot
      [] -> %{status: :starting, checked_at: nil}
    end
  rescue
    ArgumentError -> :unavailable
  end
end
