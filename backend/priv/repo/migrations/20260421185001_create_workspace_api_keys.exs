defmodule Sovra.Repo.Migrations.CreateWorkspaceApiKeys do
  use Ecto.Migration

  def change do
    create table(:workspace_api_keys, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          null: false

      add :name, :string, null: false
      add :api_key_hash, :string, null: false
      add :last_used_at, :utc_datetime
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:workspace_api_keys, [:api_key_hash])
    create index(:workspace_api_keys, [:workspace_id])
  end
end
