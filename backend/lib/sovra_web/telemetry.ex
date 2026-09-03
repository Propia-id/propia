defmodule SovraWeb.Telemetry do
  @moduledoc """
  The bridge from this app's own `:telemetry` events to New Relic metrics.

  ## What consumes telemetry here

  Almost nothing needs wiring, because `new_relic_agent` attaches its own
  instrumenters at boot:

    * Phoenix endpoint and router events become `Transaction` events, carrying
      `path`, `status` and `duration` — which is why the alert conditions read
      `Transaction` rather than any metric defined here.
    * Ecto query events become `Transaction` and `Span` attributes.
    * Oban job events become `Transaction` events carrying `oban.worker`,
      `oban.queue` and `oban.job.result`.
    * BEAM statistics arrive on their own 15s cycle as `ElixirSample` with
      `category = 'BeamStat'` (memory, run queue, process count). Those come
      from the agent's **own** sampler (`NewRelic.Sampler.Beam`, which calls
      `:erlang.statistics/1` directly) — it consumes no `:telemetry` events, so
      nothing here needs to feed it.

  This module previously declared 20 `Telemetry.Metrics` definitions and
  attached no reporter, so they measured nothing and duplicated the list above.
  It also supervised a `:telemetry_poller` configured with `measurements: []`,
  which polled nothing and which nothing read. Both are gone, along with the
  `telemetry_metrics` and `telemetry_poller` dependencies that existed only to
  serve them, and this module is no longer a supervisor — `attach_handlers/0`
  is called from `Sovra.Application` at boot.

  ## What does need wiring

  The application's own `:telemetry` events, which no library knows about.
  `attach_handlers/0` bridges them to New Relic custom metrics, so a rate or a
  latency distribution is a metric rather than something to `count(*)` over
  logs. Business *events* stay in the log (see `Sovra.Log`) — the two are
  complementary: the log answers "what happened to this credential", the metric
  answers "how often, and how slowly".

  Reporting is skipped when the agent is dormant (no `NEW_RELIC_LICENSE_KEY`),
  which is every local and test run.
  """

  @webhook_delivery [:sovra, :webhook, :delivery]

  @doc """
  Attaches the handlers that bridge this app's `:telemetry` events to New Relic.

  Idempotent: re-attaching the same handler id is a no-op, which matters when
  the application restarts inside one VM (releases, `iex -S mix`).
  """
  def attach_handlers do
    :telemetry.attach(
      "sovra-webhook-delivery-metrics",
      @webhook_delivery,
      &__MODULE__.handle_webhook_delivery/4,
      %{}
    )
    |> case do
      :ok -> :ok
      {:error, :already_exists} -> :ok
    end
  end

  @doc false
  def handle_webhook_delivery(@webhook_delivery, %{duration: duration}, metadata, _config) do
    if reporting?() do
      ms = System.convert_time_unit(duration, :native, :millisecond)

      NewRelic.report_custom_metric("Custom/Webhook/DeliveryDuration", ms)
      NewRelic.increment_custom_metric("Custom/Webhook/Delivery/#{status_class(metadata)}")
    end

    :ok
  end

  # A per-status-code metric would be unbounded; the class is what a dashboard
  # actually plots.
  defp status_class(%{status: status}) when status in 200..299, do: "ok"
  defp status_class(%{status: status}) when status in 400..499, do: "client_error"
  defp status_class(%{status: status}) when status in 500..599, do: "server_error"
  defp status_class(_metadata), do: "other"

  defp reporting? do
    case Application.get_env(:new_relic_agent, :license_key) do
      key when is_binary(key) and key != "" -> true
      _ -> false
    end
  end
end
