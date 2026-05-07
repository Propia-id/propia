defmodule Sovra.Repo.Migrations.AsyncWorkspaceProvisioning do
  use Ecto.Migration

  def up do
    alter table(:workspaces) do
      add :provisioning_status, :string, null: false, default: "pending"
      add :provisioning_error, :text
      add :provisioned_at, :utc_datetime

      modify :eoa_address, :string, null: true
      modify :eoa_key_id, :string, null: true
      modify :signing_key_id, :string, null: true
      modify :signing_public_key_x, :binary, null: true
      modify :signing_public_key_y, :binary, null: true
      modify :did, :string, null: true
    end

    execute("UPDATE workspaces SET provisioning_status = 'done', provisioned_at = inserted_at")
  end

  def down do
    # Pre-rollback shape required NOT NULL on the cryptographic columns.
    # Pending/failed workspaces have nulls and can't survive — drop them
    # along with their cascading members and api keys so the NOT NULL
    # restoration succeeds.
    execute("DELETE FROM workspaces WHERE provisioning_status <> 'done'")

    alter table(:workspaces) do
      remove :provisioning_status
      remove :provisioning_error
      remove :provisioned_at

      modify :eoa_address, :string, null: false
      modify :eoa_key_id, :string, null: false
      modify :signing_key_id, :string, null: false
      modify :signing_public_key_x, :binary, null: false
      modify :signing_public_key_y, :binary, null: false
      modify :did, :string, null: false
    end
  end
end
