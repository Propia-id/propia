defmodule Sovra.Webhooks.DeliveryJob do
  @moduledoc """
  Oban worker that delivers a signed webhook POST to one of a workspace's
  endpoints (`Sovra.Webhooks.Webhook`). The HMAC signature is computed with the
  endpoint's own secret by `Sovra.Crypto.HmacKeyStore` (`DatabaseHmacStore` —
  the secret is stored so it can be revealed to the customer once, since KMS
  HMAC keys are non-exportable).

  The endpoint is re-read at delivery time: one deleted, disabled, or no
  longer subscribed to the event since it was enqueued is skipped.

  Retry semantics:
  - 2xx → success.
  - 4xx → `:discard` (consumer bug, not transient; retrying won't help).
  - 5xx / transport error / timeout → raise → Oban retries with backoff up
    to `max_attempts` (configured at enqueue time, default 8).
  """

  use Oban.Worker, queue: :webhooks, max_attempts: 8
  use Sovra.Log

  alias Sovra.Crypto.HmacKeyStore
  alias Sovra.Repo
  alias Sovra.Webhooks.Webhook

  @impl Oban.Worker
  def perform(
        %Oban.Job{
          args: %{"webhook_id" => webhook_id, "event" => event, "payload" => payload} = args
        } = job
      ) do
    Log.adopt_job_context(job)

    Log.put_context(
      workspace_id: args["workspace_id"],
      webhook_id: webhook_id,
      event_type: event,
      delivery_id: args["delivery_id"]
    )

    case Repo.get(Webhook, webhook_id) do
      nil ->
        skip(:webhook_deleted)

      %Webhook{enabled: false} ->
        skip(:webhook_disabled)

      %Webhook{url: url, secret_key_id: key_id, events: events} ->
        if event in events,
          do: deliver(url, key_id, event, payload),
          else: skip(:event_unsubscribed)
    end
  end

  # Not a failure: the operator changed the endpoint after the event was
  # emitted. Logged so a customer asking "why no webhook" has an answer.
  defp skip(reason) do
    Log.event(:info, "webhook skipped", event: "webhook.skipped", reason: reason)
    :ok
  end

  defp deliver(url, key_id, event, payload) do
    body = Jason.encode!(payload)

    with {:ok, sig} <- HmacKeyStore.hmac(key_id, body),
         signature_header = "sha256=" <> Base.encode16(sig, case: :lower),
         start = System.monotonic_time(),
         req_opts =
           Keyword.merge(
             [
               body: body,
               headers: [
                 {"content-type", "application/json"},
                 {"x-sovra-signature", signature_header},
                 {"x-sovra-event", event}
               ],
               receive_timeout: 5_000,
               retry: false
             ],
             Application.get_env(:sovra, :webhook_req_opts, [])
           ),
         {:ok, resp} <- Req.post(url, req_opts) do
      duration = System.monotonic_time() - start

      :telemetry.execute(
        [:sovra, :webhook, :delivery],
        %{duration: duration},
        %{event: event, status: resp.status}
      )

      classify(resp.status, duration_ms(duration))
    else
      {:error, reason} ->
        Log.event(:warning, "webhook delivery transport error",
          event: "webhook.failed",
          reason: Log.reason(reason)
        )

        {:error, reason}
    end
  end

  defp duration_ms(native), do: System.convert_time_unit(native, :native, :millisecond)

  defp classify(status, ms) when status in 200..299 do
    Log.event(:info, "webhook delivered",
      event: "webhook.delivered",
      status: status,
      duration_ms: ms
    )

    :ok
  end

  # A 4xx is the consumer's bug and retrying cannot help, so the event is the
  # only record that the customer's endpoint rejected us.
  #
  # No `reason` here or on the 5xx below: the status already says whose fault
  # it was, and with webhook_id in the job context an atom restating it would
  # push these lines past New Relic's 10 attributes — see Sovra.Log.
  defp classify(status, ms) when status in 400..499 do
    Log.event(:warning, "webhook delivery rejected by consumer",
      event: "webhook.discarded",
      status: status,
      duration_ms: ms
    )

    {:discard, {:client_error, status}}
  end

  defp classify(status, ms) do
    Log.event(:warning, "webhook delivery failed, will retry",
      event: "webhook.failed",
      status: status,
      duration_ms: ms
    )

    {:error, {:remote_error, status}}
  end
end
