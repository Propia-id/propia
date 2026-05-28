defmodule Sovra.DID.DocumentCache do
  @moduledoc """
  ETS-backed cache for DID resolution results, with single-flight coalescing.

  Caches both successful resolutions and negative results so a transient
  outage at the upstream resolver doesn't trigger a burst of retries on
  every verification attempt. Each entry has its own expiry; a periodic
  cleanup tick reaps expired rows.

  `fetch_or_wait/4` is the recommended entrypoint for cache-and-fetch
  flows: concurrent callers for the same uncached DID share a single
  in-flight fetch instead of stampeding the upstream resolver. The
  positive/negative TTLs are routed automatically based on whether the
  fetcher returns `{:ok, _}` or `{:error, _}`.

  The fetcher runs in the **caller's** process, not in the cache GenServer.
  This preserves the caller's process-local state (e.g., `Req.Test` stubs,
  Mox expectations, OpenTelemetry context). The GenServer only coordinates
  who runs the fetch and broadcasts the result to waiters.

  Keyed by the full DID string. Values are arbitrary terms — the caller
  decides whether to store JWK lists, error tuples, or anything else.
  """

  use GenServer

  @table :sovra_did_document_cache
  @cleanup_interval :timer.seconds(60)
  @waiter_timeout :timer.seconds(60)

  # ── Client API ──────────────────────────────────────────────

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Look up a cached entry. Returns `{:hit, term}` if present and unexpired,
  `:miss` otherwise.
  """
  @spec get(String.t()) :: {:hit, term} | :miss
  def get(did) when is_binary(did) do
    case :ets.lookup(@table, did) do
      [{^did, value, expires_at}] ->
        if System.system_time(:second) < expires_at do
          {:hit, value}
        else
          :miss
        end

      _ ->
        :miss
    end
  rescue
    ArgumentError -> :miss
  end

  @doc "Store `value` under `did` for `ttl_seconds` seconds."
  @spec put(String.t(), term, pos_integer) :: :ok
  def put(did, value, ttl_seconds)
      when is_binary(did) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    expires_at = System.system_time(:second) + ttl_seconds
    :ets.insert(@table, {did, value, expires_at})
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc "Remove `did` from the cache. Always returns `:ok`."
  @spec invalidate(String.t()) :: :ok
  def invalidate(did) when is_binary(did) do
    :ets.delete(@table, did)
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc """
  Return the cached result for `did`, or run `fetcher` (coalescing concurrent
  callers) and cache its result before returning. Successful results are
  cached for `positive_ttl_s`; error tuples for `negative_ttl_s`.

  `fetcher` is a 0-arity function returning `{:ok, term} | {:error, term}`.
  If it raises or exits, all waiters receive `{:error, :fetch_crashed}` and
  no cache entry is written, so the next caller will retry.

  The first concurrent caller for an uncached DID runs the fetcher; the
  others block until the result is broadcast.
  """
  @spec fetch_or_wait(
          String.t(),
          (-> {:ok, term} | {:error, term}),
          pos_integer,
          pos_integer
        ) :: {:ok, term} | {:error, term}
  def fetch_or_wait(did, fetcher, positive_ttl_s, negative_ttl_s)
      when is_binary(did) and is_function(fetcher, 0) and
             is_integer(positive_ttl_s) and positive_ttl_s > 0 and
             is_integer(negative_ttl_s) and negative_ttl_s > 0 do
    case get(did) do
      {:hit, result} ->
        result

      :miss ->
        case GenServer.call(__MODULE__, {:claim, did}, :infinity) do
          {:hit, result} ->
            result

          :go ->
            run_and_publish(did, fetcher, positive_ttl_s, negative_ttl_s)

          {:wait, wait_ref} ->
            receive do
              {__MODULE__, :resolved, ^wait_ref, result} -> result
            after
              @waiter_timeout -> {:error, :fetch_timeout}
            end
        end
    end
  end

  defp run_and_publish(did, fetcher, positive_ttl_s, negative_ttl_s) do
    result =
      try do
        fetcher.()
      rescue
        _ -> {:error, :fetch_crashed}
      catch
        _, _ -> {:error, :fetch_crashed}
      end

    ttl =
      case result do
        {:ok, _} -> positive_ttl_s
        _ -> negative_ttl_s
      end

    # Only cache real outcomes; let crashes (which include exits) retry.
    case result do
      {:error, :fetch_crashed} -> :ok
      _ -> put(did, result, ttl)
    end

    GenServer.cast(__MODULE__, {:resolved, did, self(), result})
    result
  end

  # ── GenServer callbacks ─────────────────────────────────────

  @impl true
  def init(_) do
    :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
    schedule_cleanup()
    {:ok, %{inflight: %{}}}
  end

  @impl true
  def handle_call({:claim, did}, {caller_pid, _tag}, state) do
    # Re-check the cache — another fetcher may have published since the
    # caller's get/1 short-circuit.
    case get(did) do
      {:hit, result} ->
        {:reply, {:hit, result}, state}

      :miss ->
        case Map.get(state.inflight, did) do
          nil ->
            leader_ref = Process.monitor(caller_pid)

            entry = %{leader_pid: caller_pid, leader_ref: leader_ref, waiters: []}
            {:reply, :go, %{state | inflight: Map.put(state.inflight, did, entry)}}

          %{waiters: waiters} = entry ->
            wait_ref = make_ref()
            updated = %{entry | waiters: [{caller_pid, wait_ref} | waiters]}

            {:reply, {:wait, wait_ref},
             %{state | inflight: Map.put(state.inflight, did, updated)}}
        end
    end
  end

  @impl true
  def handle_cast({:resolved, did, leader_pid, result}, state) do
    case state.inflight[did] do
      %{leader_pid: ^leader_pid, leader_ref: leader_ref, waiters: waiters} ->
        Process.demonitor(leader_ref, [:flush])

        Enum.each(waiters, fn {pid, ref} ->
          send(pid, {__MODULE__, :resolved, ref, result})
        end)

        {:noreply, %{state | inflight: Map.delete(state.inflight, did)}}

      _ ->
        # Stale (e.g., DOWN already cleared this entry).
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Enum.find(state.inflight, fn {_did, %{leader_ref: r}} -> r == ref end) do
      {did, %{waiters: waiters}} ->
        err = {:error, :fetch_crashed}

        Enum.each(waiters, fn {pid, wait_ref} ->
          send(pid, {__MODULE__, :resolved, wait_ref, err})
        end)

        {:noreply, %{state | inflight: Map.delete(state.inflight, did)}}

      nil ->
        {:noreply, state}
    end
  end

  def handle_info(:cleanup, state) do
    now = System.system_time(:second)
    :ets.select_delete(@table, [{{:"$1", :"$2", :"$3"}, [{:<, :"$3", now}], [true]}])
    schedule_cleanup()
    {:noreply, state}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
