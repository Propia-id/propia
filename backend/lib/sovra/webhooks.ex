defmodule Sovra.Webhooks do
  @moduledoc """
  Outbound webhooks: the endpoints a workspace configures, and delivery of its
  events to them.

  A workspace has a bounded number of endpoints (`Sovra.Webhooks.Webhook`),
  each with its own URL, subscribed event types and HMAC secret (in the
  configured `Sovra.Crypto.HmacKeyStore`). `enqueue/3` fans an event out into
  one `DeliveryJob` per enabled endpoint subscribed to it, so an endpoint that
  fails retries on its own schedule without holding back the others. Every
  delivery of one event carries the same payload `id`, which is what a
  receiver deduplicates on.

  Enqueueing inside a caller's `Ecto.Multi` / `Repo.transaction` is safe:
  Oban persists the jobs to the same `Repo`, so the enqueue rolls back if
  the surrounding transaction rolls back.
  """

  use Sovra.Log

  import Ecto.Query

  alias Sovra.Crypto.HmacKeyStore
  alias Sovra.Repo
  alias Sovra.Webhooks.DeliveryJob
  alias Sovra.Webhooks.Webhook
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  @event_types ~w(
    identity.did-generated
    credential.issued
    credential.revoked
    credential.suspended
    credential.unsuspended
    credential.status-change-failed
    document.status-changed
    presentation.verified
    presentation.failed
  )

  # Every event becomes one job per subscribed endpoint, so the cap bounds the
  # fan-out one workspace can put on the webhooks queue.
  @max_webhooks_per_workspace 10

  @doc "Every event type an endpoint can subscribe to."
  def event_types, do: @event_types

  def max_webhooks_per_workspace, do: @max_webhooks_per_workspace

  # ── Endpoints ──────────────────────────────────────────

  @doc "The workspace's endpoints, oldest first."
  def list_webhooks(workspace_id) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id) do
      webhooks =
        from(w in Webhook,
          where: w.workspace_id == ^workspace.id,
          order_by: [asc: w.inserted_at, asc: w.id]
        )
        |> Repo.all()

      {:ok, webhooks}
    end
  end

  @doc """
  Create an endpoint. Generates its signing secret and returns the plaintext
  **exactly once**, alongside the record.

  Returns `{:error, :webhook_limit_reached}` once the workspace has
  `max_webhooks_per_workspace/0` endpoints.
  """
  def create_webhook(workspace_id, attrs) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id) do
      Repo.transaction(fn ->
        with :ok <- ensure_capacity(workspace.id),
             {:ok, %{key_id: key_id, plaintext: secret}} <- HmacKeyStore.generate_hmac_key(),
             {:ok, webhook} <-
               %Webhook{workspace_id: workspace.id, secret_key_id: key_id}
               |> Webhook.create_changeset(attrs)
               |> Repo.insert() do
          %{webhook: webhook, secret: secret}
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      end)
      |> tap(fn
        {:ok, %{webhook: webhook}} ->
          # Adds a destination for the workspace's event stream; the record of
          # who pointed credential events where. Host only — see webhook_host/1.
          Log.event(:info, "workspace webhook created",
            event: "workspace.webhook.created",
            workspace_id: webhook.workspace_id,
            webhook_id: webhook.id,
            webhook_host: webhook_host(webhook.url),
            events: Enum.join(webhook.events, ","),
            enabled: webhook.enabled
          )

        {:error, _} ->
          :ok
      end)
    end
  end

  # The row lock serialises concurrent creates in one workspace, so two cannot
  # both count nine and insert a tenth and eleventh.
  defp ensure_capacity(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id, select: w.id, lock: "FOR UPDATE")
    |> Repo.one!()

    count = Repo.aggregate(from(w in Webhook, where: w.workspace_id == ^workspace_id), :count)

    if count < @max_webhooks_per_workspace, do: :ok, else: {:error, :webhook_limit_reached}
  end

  @doc "Change an endpoint's URL, subscribed events, or enabled flag."
  def update_webhook(workspace_id, webhook_id, attrs) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id),
         {:ok, webhook} <- get_webhook(workspace.id, webhook_id),
         {:ok, updated} <- webhook |> Webhook.update_changeset(attrs) |> Repo.update() do
      log_webhook_updated(webhook, updated)
      {:ok, updated}
    end
  end

  # Redirecting, narrowing or pausing an endpoint changes what a customer
  # receives, and "our webhooks stopped arriving" is otherwise
  # indistinguishable from a delivery failure.
  defp log_webhook_updated(%Webhook{} = before, %Webhook{} = updated) do
    if Map.take(before, [:url, :events, :enabled]) != Map.take(updated, [:url, :events, :enabled]) do
      Log.event(:info, "workspace webhook updated",
        event: "workspace.webhook.updated",
        workspace_id: updated.workspace_id,
        webhook_id: updated.id,
        previous_webhook_host: webhook_host(before.url),
        webhook_host: webhook_host(updated.url),
        events: Enum.join(updated.events, ","),
        enabled: updated.enabled
      )
    end
  end

  @doc "Delete an endpoint and its signing secret."
  def delete_webhook(workspace_id, webhook_id) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id),
         {:ok, webhook} <- get_webhook(workspace.id, webhook_id) do
      Repo.transaction(fn ->
        with {:ok, deleted} <- Repo.delete(webhook),
             :ok <- HmacKeyStore.delete(webhook.secret_key_id) do
          deleted
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      end)
      |> tap(fn
        {:ok, deleted} ->
          Log.event(:info, "workspace webhook deleted",
            event: "workspace.webhook.deleted",
            workspace_id: deleted.workspace_id,
            webhook_id: deleted.id,
            webhook_host: webhook_host(deleted.url)
          )

        {:error, _} ->
          :ok
      end)
    end
  end

  @doc """
  Rotate an endpoint's signing secret. Returns the new plaintext exactly once;
  the previous secret stops verifying immediately.
  """
  def rotate_webhook_secret(workspace_id, webhook_id) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id),
         {:ok, webhook} <- get_webhook(workspace.id, webhook_id),
         {:ok, %{plaintext: secret}} <- HmacKeyStore.rotate(webhook.secret_key_id) do
      # After the rotation lands, not before. Invalidates the customer's
      # signature verification until they store the new secret, so a burst of
      # signature complaints traces back here.
      Log.event(:info, "workspace webhook secret rotated",
        event: "workspace.webhook.secret_rotated",
        workspace_id: webhook.workspace_id,
        webhook_id: webhook.id
      )

      {:ok, %{webhook: webhook, secret: secret}}
    end
  end

  defp get_webhook(workspace_id, webhook_id) do
    case Repo.get_by(Webhook, id: webhook_id, workspace_id: workspace_id) do
      nil -> {:error, :webhook_not_found}
      webhook -> {:ok, webhook}
    end
  end

  # HOST ONLY, never the full URL. A webhook URL routinely carries a shared
  # secret in its path or query (`/hooks/sovra?token=…`), and these logs leave
  # the host for New Relic. The host answers what the events exist for — did
  # the destination move — and `workspace_webhooks.url` has the rest for anyone
  # with database access.
  defp webhook_host(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) -> host
      _ -> "unparseable"
    end
  end

  # ── Delivery ───────────────────────────────────────────

  @doc """
  Build a webhook payload for `event_type` + `data` and enqueue one delivery
  per enabled endpoint of the workspace subscribed to `event_type`. Returns
  `{:ok, jobs}` — an empty list when nothing is subscribed. `DeliveryJob`
  re-checks the endpoint, so one disabled, unsubscribed or deleted after the
  enqueue is skipped.
  """
  def enqueue(workspace_id, event_type, data)
      when event_type in @event_types and is_map(data) do
    payload = %{
      "event" => event_type,
      "id" => Ecto.UUID.generate(),
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "workspace_id" => workspace_id,
      "data" => data
    }

    case subscribed_webhooks(workspace_id, event_type) do
      [] ->
        # Not a failure: nothing is listening for this event. Logged so a
        # customer asking "why no webhooks" has an answer.
        Log.event(:info, "webhook skipped, no subscribed endpoint",
          event: "webhook.skipped",
          reason: :no_subscribed_webhook,
          delivery_id: payload["id"],
          workspace_id: workspace_id,
          event_type: event_type
        )

        {:ok, []}

      webhooks ->
        webhooks
        |> Enum.reduce_while({:ok, []}, fn webhook, {:ok, jobs} ->
          case insert_delivery(webhook, event_type, payload) do
            {:ok, job} -> {:cont, {:ok, [job | jobs]}}
            {:error, _} = error -> {:halt, error}
          end
        end)
        |> case do
          {:ok, jobs} -> {:ok, Enum.reverse(jobs)}
          error -> error
        end
    end
  end

  defp subscribed_webhooks(workspace_id, event_type) do
    from(w in Webhook,
      where: w.workspace_id == ^workspace_id and w.enabled and ^event_type in w.events,
      order_by: [asc: w.inserted_at, asc: w.id]
    )
    |> Repo.all()
  end

  defp insert_delivery(%Webhook{} = webhook, event_type, payload) do
    # delivery_id is the payload's "id" — the value the customer sees in the
    # request body — so a "we never received webhook X" ticket resolves to one
    # NRQL query; webhook_id says which of the workspace's endpoints it was.
    # Log.job_args/1 carries request_id across the job boundary.
    %{
      webhook_id: webhook.id,
      workspace_id: webhook.workspace_id,
      event: event_type,
      delivery_id: payload["id"],
      payload: payload
    }
    |> Log.job_args()
    |> DeliveryJob.new(queue: :webhooks, max_attempts: 8)
    |> Oban.insert()
    |> tap(fn
      {:ok, _job} ->
        Log.event(:info, "webhook enqueued",
          event: "webhook.enqueued",
          delivery_id: payload["id"],
          workspace_id: webhook.workspace_id,
          webhook_id: webhook.id,
          event_type: event_type
        )

      {:error, reason} ->
        Log.event(:error, "webhook enqueue failed",
          event: "webhook.enqueue_failed",
          delivery_id: payload["id"],
          workspace_id: webhook.workspace_id,
          webhook_id: webhook.id,
          event_type: event_type,
          reason: Log.reason(reason)
        )
    end)
  end
end
