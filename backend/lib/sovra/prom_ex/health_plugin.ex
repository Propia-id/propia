defmodule Sovra.PromEx.HealthPlugin do
  @moduledoc """
  PromEx plugin for the readiness checks.

  Measurements come from `Sovra.Health`'s telemetry, so the probe and the alerts
  read the same verdict — an alert can never disagree with what `/ready` reports
  on the same node.

  `sovra_health_last_check_timestamp_seconds` is the staleness guard, and it is
  not optional: every other series here is a `last_value`, so a monitor that
  dies keeps serving its final verdict forever. This is the same trap
  `RelayerBalanceStale` exists to cover.

  Names carry the `sovra_` prefix, not PromEx's, since alert rules reference
  them directly.
  """

  use PromEx.Plugin

  @check_event [:sovra, :health, :check]
  @cycle_event [:sovra, :health, :cycle]

  @impl true
  def event_metrics(_opts) do
    Event.build(:health_event_metrics, [
      last_value([:sovra, :health, :dependency, :up],
        event_name: @check_event,
        measurement: :up,
        description:
          "1 when a dependency passed its last check, else 0. `chain_id` and `chain_name` " <>
            "are empty for everything but `dependency=\"rpc\"`; Prometheus treats an empty " <>
            "label as absent, so one series name covers every dependency.",
        tags: [:dependency, :chain_id, :chain_name]
      ),
      distribution([:sovra, :health, :check, :duration, :milliseconds],
        event_name: @check_event,
        measurement: :duration_ms,
        description:
          "Wall-clock time of a single dependency check. A check killed by the cycle " <>
            "timeout is recorded at the timeout, not at its true duration.",
        tags: [:dependency],
        reporter_options: [buckets: [10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000]]
      ),
      last_value([:sovra, :health, :ready],
        event_name: @cycle_event,
        measurement: :ready,
        description:
          "1 when every dependency passed the last cycle on this node — the same verdict " <>
            "`/ready` serves. Node-scoped: a node is not ready, the service may still be."
      ),
      last_value([:sovra, :health, :last_check, :timestamp, :seconds],
        event_name: @cycle_event,
        measurement: :timestamp_seconds,
        description:
          "Unix time of the last completed check cycle. Every other series here is a " <>
            "last_value, so without this a dead monitor reads as permanently healthy."
      )
    ])
  end
end
