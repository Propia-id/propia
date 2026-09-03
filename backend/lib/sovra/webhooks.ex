defmodule Sovra.Webhooks do
  @moduledoc """
  Outbound webhook delivery. Events are enqueued to Oban; the `DeliveryJob`
  worker signs the payload with the workspace's HMAC key (via the configured
  `Sovra.Crypto.HmacKeyStore`) and POSTs it to the workspace's `webhook_url`.

  Enqueueing inside a caller's `Ecto.Multi` / `Repo.transaction` is safe:
  Oban persists the job to the same `Repo`, so the enqueue rolls back if
  the surrounding transaction rolls back.
  """

  use Sovra.Log

  alias Sovra.Webhooks.DeliveryJob

  @doc """
  Build a webhook payload for `event_type` + `data` and enqueue its delivery.
  No-ops silently when the workspace has no `webhook_url` configured —
  `DeliveryJob` double-checks so the policy is enforced even if callers
  race against webhook-url changes.
  """
  def enqueue(workspace_id, event_type, data) when is_binary(event_type) and is_map(data) do
    payload = %{
      "event" => event_type,
      "id" => Ecto.UUID.generate(),
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "workspace_id" => workspace_id,
      "data" => data
    }

    # delivery_id is the payload's "id" — the value the customer sees in the
    # request body — so a "we never received webhook X" ticket resolves to one
    # NRQL query. Log.job_args/1 carries request_id across the job boundary.
    %{
      workspace_id: workspace_id,
      event: event_type,
      delivery_id: payload["id"],
      payload: payload
    }
    |> Log.job_args()
    |> DeliveryJob.new(queue: :webhooks, max_attempts: 8)
    |> Oban.insert()
    |> tap(fn
      {:ok, _job} ->
        # delivery_id is the payload's "id", which the customer sees in the
        # request body — the only value that makes "we never received webhook
        # abc-123" answerable.
        Log.event(:info, "webhook enqueued",
          event: "webhook.enqueued",
          delivery_id: payload["id"],
          workspace_id: workspace_id,
          event_type: event_type
        )

      {:error, reason} ->
        Log.event(:error, "webhook enqueue failed",
          event: "webhook.enqueue_failed",
          delivery_id: payload["id"],
          workspace_id: workspace_id,
          event_type: event_type,
          reason: Log.reason(reason)
        )
    end)
  end
end
