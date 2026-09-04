defmodule Sovra.Ethereum.Relayer.BalanceMonitor do
  @moduledoc """
  Polls the relayer's balance per chain and emits it as telemetry, which
  `Sovra.PromEx.RelayerPlugin` turns into gauges. Read-only: it never submits a
  transaction and never gates one.

  `init/1` does no I/O, so a signer or RPC that is down cannot fail boot; the
  first poll is scheduled, and jittered so nodes restarted together do not poll
  a shared endpoint in lockstep.
  """

  use GenServer

  alias Sovra.Ethereum.{BalanceReader, Chains, Relayer}

  require Logger

  @balance_event [:sovra, :relayer, :balance]
  @poll_event [:sovra, :relayer, :balance, :poll]

  @default_interval_ms :timer.minutes(1)
  @default_chain_timeout_ms 10_000

  @doc false
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Runs one cycle synchronously and returns `%{chain_id => result}`. For tests;
  `timeout` must exceed `:chain_timeout_ms`.
  """
  @spec poll_now(timeout()) :: %{pos_integer() => {:ok, non_neg_integer()} | {:error, term()}}
  def poll_now(timeout \\ 30_000), do: GenServer.call(__MODULE__, :poll, timeout)

  @impl true
  def init(opts) do
    config = Keyword.merge(Application.get_env(:sovra, __MODULE__, []), opts)

    if Keyword.get(config, :enabled, false) do
      state = %{
        interval_ms: Keyword.get(config, :interval_ms, @default_interval_ms),
        chain_timeout_ms: Keyword.get(config, :chain_timeout_ms, @default_chain_timeout_ms),
        reader: Keyword.get_lazy(config, :reader, &BalanceReader.impl/0)
      }

      Process.send_after(self(), :poll, :rand.uniform(state.interval_ms))
      {:ok, state}
    else
      :ignore
    end
  end

  @impl true
  def handle_info(:poll, state) do
    _ = poll_all(state)
    Process.send_after(self(), :poll, next_delay(state.interval_ms))
    {:noreply, state}
  end

  @impl true
  def handle_call(:poll, _from, state), do: {:reply, poll_all(state), state}

  # ±10% so ticks that start together do not stay together.
  defp next_delay(interval_ms) do
    spread = max(div(interval_ms, 5), 1)
    interval_ms - div(spread, 2) + :rand.uniform(spread)
  end

  defp poll_all(state) do
    chains =
      Chains.all()
      |> Enum.map(fn {chain_id, chain} -> {chain_id, chain.name} end)
      |> Enum.sort()

    case Relayer.cached_address() do
      {:ok, address} ->
        read_all(state, chains, address)

      {:error, reason} ->
        Logger.warning("relayer.balance_monitor signer_unavailable err=#{inspect(reason)}")
        # Per chain, so every chain always has a poll series to alert on.
        Enum.each(chains, &emit_poll(&1, "signer_unavailable", 0))
        %{}
    end
  end

  defp read_all(_state, [], _address), do: %{}

  defp read_all(state, chains, address) do
    chains
    |> Task.async_stream(
      fn {chain_id, _name} = chain -> {chain, timed_read(state, chain_id, address)} end,
      # A bounded timeout, not `:infinity`: ethereumex has no receive timeout
      # configured, so one unresponsive endpoint would otherwise hang the cycle.
      max_concurrency: length(chains),
      timeout: state.chain_timeout_ms,
      on_timeout: :kill_task,
      zip_input_on_exit: true,
      ordered: false
    )
    |> Enum.reduce(%{}, fn item, acc -> collect(item, acc, state) end)
  end

  defp timed_read(state, chain_id, address) do
    started = System.monotonic_time(:millisecond)
    result = safe_read(state.reader, chain_id, address)
    {result, System.monotonic_time(:millisecond) - started}
  end

  # Tasks are linked here, so an unexpected raise would take the monitor down.
  defp safe_read(reader, chain_id, address) do
    reader.get_balance(chain_id, address)
  rescue
    error -> {:error, {:exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp collect({:ok, {{chain_id, _} = chain, {result, duration_ms}}}, acc, _state) do
    emit(chain, result, duration_ms)
    Map.put(acc, chain_id, result)
  end

  # `zip_input_on_exit: true` hands the input back, so we know which chain died.
  defp collect({:exit, {{chain_id, _} = chain, reason}}, acc, state) do
    result = {:error, reason}
    emit(chain, result, state.chain_timeout_ms)
    Map.put(acc, chain_id, result)
  end

  defp emit({chain_id, chain_name} = chain, {:ok, wei}, duration_ms) do
    :telemetry.execute(
      @balance_event,
      %{wei: wei, timestamp_seconds: System.system_time(:second)},
      %{chain_id: chain_id, chain_name: chain_name}
    )

    emit_poll(chain, "ok", duration_ms)
    Logger.info("relayer.balance chain=#{chain_id} wei=#{wei} took=#{duration_ms}ms")
  end

  defp emit({chain_id, _} = chain, {:error, reason}, duration_ms) do
    emit_poll(chain, result_label(reason), duration_ms)

    Logger.warning(
      "relayer.balance_failed chain=#{chain_id} took=#{duration_ms}ms err=#{inspect(reason)}"
    )
  end

  defp emit_poll({chain_id, chain_name}, result, duration_ms) do
    :telemetry.execute(@poll_event, %{duration_ms: duration_ms}, %{
      chain_id: chain_id,
      chain_name: chain_name,
      result: result
    })
  end

  # A metric label, so it stays a closed set; the raw reason goes to the log.
  defp result_label(:chain_rpc_not_configured), do: "unconfigured"
  defp result_label(:unknown_chain), do: "unconfigured"
  defp result_label(:invalid_uint_response), do: "decode_error"
  defp result_label(:timeout), do: "timeout"
  defp result_label(_reason), do: "rpc_error"
end
