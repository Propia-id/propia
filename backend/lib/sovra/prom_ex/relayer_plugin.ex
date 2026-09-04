defmodule Sovra.PromEx.RelayerPlugin do
  @moduledoc """
  PromEx plugin for the single-key relayer.

  Measurements come from `Sovra.Ethereum.Relayer.BalanceMonitor`'s telemetry.
  Configuration (floors, chain inventory, address) is a separate polling group
  so it stays present when the chain's RPC or the signer is down — the alert
  rules need a right-hand side to compare against.

  Names carry the `sovra_` prefix, not PromEx's, since alert rules reference
  them directly (matching `sovra_pg_backup_last_success_timestamp_seconds`).
  """

  use PromEx.Plugin

  alias Sovra.Ethereum.{Chains, Relayer}

  require Logger

  @balance_event [:sovra, :relayer, :balance]
  @poll_event [:sovra, :relayer, :balance, :poll]
  @config_event [:sovra, :relayer, :config]

  @impl true
  def event_metrics(_opts) do
    Event.build(:relayer_balance_event_metrics, [
      last_value([:sovra, :relayer, :balance, :wei],
        event_name: @balance_event,
        measurement: :wei,
        description:
          "Relayer balance in wei at the last successful poll. A failed poll leaves it " <>
            "untouched, so pair it with the last-success timestamp. Stored as a float64, " <>
            "so it is fine for thresholds and not for accounting.",
        tags: [:chain_id, :chain_name]
      ),
      last_value([:sovra, :relayer, :balance, :last_success, :timestamp, :seconds],
        event_name: @balance_event,
        measurement: :timestamp_seconds,
        description: "Unix time of the last successful relayer balance read for this chain.",
        tags: [:chain_id, :chain_name]
      ),
      counter([:sovra, :relayer, :balance, :poll, :total],
        event_name: @poll_event,
        description: "Relayer balance poll attempts, by outcome.",
        tags: [:chain_id, :chain_name, :result]
      ),
      distribution([:sovra, :relayer, :balance, :poll, :duration, :milliseconds],
        event_name: @poll_event,
        measurement: :duration_ms,
        description: "Wall-clock time of a single relayer balance read.",
        tags: [:chain_id, :chain_name, :result],
        reporter_options: [buckets: [50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000]]
      )
    ])
  end

  @impl true
  def polling_metrics(opts) do
    poll_rate = Keyword.get(opts, :poll_rate, 60_000)

    Polling.build(
      :relayer_config_polling_metrics,
      poll_rate,
      {__MODULE__, :execute_config_metrics, []},
      [
        last_value([:sovra, :relayer, :balance, :threshold, :wei],
          event_name: @config_event ++ [:threshold],
          measurement: :wei,
          description:
            "Configured low-balance floor in wei, so one alert rule pair covers every chain.",
          tags: [:chain_id, :chain_name, :severity]
        ),
        last_value([:sovra, :relayer, :chain, :info],
          event_name: @config_event ++ [:chain],
          measurement: :value,
          description:
            "One series per known chain, value always 1. `configured=false` means the " <>
              "chain is known but its on-chain registries are not configured.",
          tags: [:chain_id, :chain_name, :configured]
        ),
        last_value([:sovra, :relayer, :address, :info],
          event_name: @config_event ++ [:address],
          measurement: :value,
          description: "The relayer's address, carried as a label. The value is always 1.",
          tags: [:address]
        ),
        last_value([:sovra, :relayer, :address, :resolved],
          event_name: @config_event ++ [:address_status],
          measurement: :value,
          description: "1 when the relayer address could be derived from the signer, else 0."
        )
      ],
      # A malformed chain map must not permanently detach the poller.
      detach_on_error: false
    )
  end

  @doc false
  def execute_config_metrics do
    emit_chain_metrics()
    emit_address_metrics()
  end

  defp emit_chain_metrics do
    thresholds = Application.get_env(:sovra, :relayer_balance_thresholds, %{})

    Enum.each(Chains.all(), fn {chain_id, chain} ->
      :telemetry.execute(@config_event ++ [:chain], %{value: 1}, %{
        chain_id: chain_id,
        chain_name: chain.name,
        configured: to_string(Chains.configured?(chain_id))
      })

      for {severity, wei} <- Map.get(thresholds, chain_id, %{}), is_integer(wei) do
        :telemetry.execute(@config_event ++ [:threshold], %{wei: wei}, %{
          chain_id: chain_id,
          chain_name: chain.name,
          severity: to_string(severity)
        })
      end
    end)
  end

  defp emit_address_metrics do
    case Relayer.cached_address() do
      {:ok, address} ->
        :telemetry.execute(@config_event ++ [:address], %{value: 1}, %{
          address: Relayer.hex(address)
        })

        :telemetry.execute(@config_event ++ [:address_status], %{value: 1}, %{})

      {:error, reason} ->
        Logger.warning("relayer.address_unresolved err=#{inspect(reason)}")
        :telemetry.execute(@config_event ++ [:address_status], %{value: 0}, %{})
    end
  end
end
