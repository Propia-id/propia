defmodule Sovra.Webhooks do
  @moduledoc """
  Outbound webhook delivery. Events are enqueued to Oban; the `DeliveryJob`
  worker signs the payload with the workspace's HMAC key (via the configured
  `Sovra.Crypto.HmacKeyStore`) and POSTs it to the workspace's `webhook_url`.

  Enqueueing inside a caller's `Ecto.Multi` / `Repo.transaction` is safe:
  Oban persists the job to the same `Repo`, so the enqueue rolls back if
  the surrounding transaction rolls back.
  """

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

    %{workspace_id: workspace_id, event: event_type, payload: payload}
    |> DeliveryJob.new(queue: :webhooks, max_attempts: 8)
    |> Oban.insert()
  end
end
