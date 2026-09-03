defmodule SovraWeb.TelemetryTest do
  @moduledoc """
  The webhook delivery telemetry event existed and nothing consumed it, the
  same way `metrics/0` declared 20 metrics and attached no reporter. These
  assert the bridge is attached and that it stays inert when the New Relic
  agent is dormant, which is every local and CI run.
  """

  use ExUnit.Case, async: false

  @webhook_delivery [:sovra, :webhook, :delivery]

  test "the webhook delivery handler is attached at boot" do
    handlers = :telemetry.list_handlers(@webhook_delivery)

    assert Enum.any?(handlers, &(&1.id == "sovra-webhook-delivery-metrics"))
  end

  test "attaching twice is a no-op, so a supervisor restart is safe" do
    assert SovraWeb.Telemetry.attach_handlers() == :ok
    assert SovraWeb.Telemetry.attach_handlers() == :ok

    assert @webhook_delivery
           |> :telemetry.list_handlers()
           |> Enum.count(&(&1.id == "sovra-webhook-delivery-metrics")) == 1
  end

  test "executing the event does not raise while the agent is dormant" do
    # No NEW_RELIC_LICENSE_KEY in test, so the handler must not touch the
    # agent's harvesters — a telemetry handler that raises is detached, which
    # would silently disable the metric in production too.
    for status <- [200, 404, 503, nil] do
      assert :telemetry.execute(@webhook_delivery, %{duration: 1_000_000}, %{
               event: "credential.issued",
               status: status
             }) == :ok
    end

    assert Enum.any?(
             :telemetry.list_handlers(@webhook_delivery),
             &(&1.id == "sovra-webhook-delivery-metrics")
           )
  end

  test "metrics/0 is gone rather than left declaring metrics nobody reads" do
    refute function_exported?(SovraWeb.Telemetry, :metrics, 0)
  end
end
