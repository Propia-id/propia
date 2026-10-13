defmodule Sovra.Repo.Migrations.CreateWorkspaceWebhooks do
  use Ecto.Migration

  # Frozen here rather than read from `Sovra.Webhooks.event_types/0`: a
  # migrated URL keeps receiving what it received on the day this ran, and the
  # migration must mean the same thing once the catalogue grows.
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

  @pending_states "('available', 'scheduled', 'retryable')"

  def up do
    create table(:workspace_webhooks, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          null: false

      add :url, :text, null: false
      add :events, {:array, :string}, null: false
      add :enabled, :boolean, null: false, default: true
      add :secret_key_id, :string, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:workspace_webhooks, [:workspace_id])
    create unique_index(:workspace_webhooks, [:secret_key_id])

    create constraint(:workspace_webhooks, :workspace_webhooks_events_not_empty,
             check: "cardinality(events) > 0"
           )

    # A configured URL becomes an endpoint subscribed to everything, keeping
    # its secret so the customer's receiver goes on verifying signatures.
    execute("""
    INSERT INTO workspace_webhooks
      (id, workspace_id, url, events, enabled, secret_key_id, inserted_at, updated_at)
    SELECT gen_random_uuid(), id, webhook_url, #{events_literal()}, true,
           webhook_secret_key_id, now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc'
    FROM workspaces
    WHERE webhook_url IS NOT NULL AND webhook_secret_key_id IS NOT NULL
    """)

    # A secret with no URL signed nothing, and nothing references it once the
    # column is gone.
    execute("""
    DELETE FROM stored_keys
    WHERE key_id IN (
      SELECT webhook_secret_key_id FROM workspaces
      WHERE webhook_url IS NULL AND webhook_secret_key_id IS NOT NULL
    )
    """)

    # Deliveries still queued were addressed to the workspace; each now names
    # the endpoint its URL became. Those for a workspace with no URL were
    # going to be skipped anyway.
    execute("""
    UPDATE oban_jobs j
    SET args = j.args || jsonb_build_object('webhook_id', w.id)
    FROM workspace_webhooks w
    WHERE j.worker = 'Sovra.Webhooks.DeliveryJob'
      AND j.state IN #{@pending_states}
      AND w.workspace_id::text = j.args->>'workspace_id'
    """)

    execute("""
    UPDATE oban_jobs
    SET state = 'cancelled', cancelled_at = now() AT TIME ZONE 'utc'
    WHERE worker = 'Sovra.Webhooks.DeliveryJob'
      AND state IN #{@pending_states}
      AND NOT args ? 'webhook_id'
    """)

    alter table(:workspaces) do
      remove :webhook_url
      remove :webhook_secret_key_id
    end
  end

  # Restores each workspace's oldest endpoint as its single webhook. The
  # secrets of any other endpoint stay in `stored_keys`, unreferenced.
  def down do
    alter table(:workspaces) do
      add :webhook_url, :string
      add :webhook_secret_key_id, :string
    end

    execute("""
    UPDATE workspaces ws
    SET webhook_url = w.url, webhook_secret_key_id = w.secret_key_id
    FROM (
      SELECT DISTINCT ON (workspace_id) workspace_id, url, secret_key_id
      FROM workspace_webhooks
      ORDER BY workspace_id, inserted_at, id
    ) w
    WHERE ws.id = w.workspace_id
    """)

    drop table(:workspace_webhooks)
  end

  defp events_literal do
    "ARRAY[" <> Enum.map_join(@event_types, ", ", &"'#{&1}'") <> "]::varchar[]"
  end
end
