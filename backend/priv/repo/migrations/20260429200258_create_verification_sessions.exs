defmodule Sovra.Repo.Migrations.CreateVerificationSessions do
  use Ecto.Migration

  def change do
    create table(:verification_sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :dcql_query, :map, null: false
      add :nonce, :string, null: false
      add :state, :string, null: false
      add :status, :string, null: false, default: "pending"
      add :holder_did, :string
      add :presentation_data, :map
      add :error, :string
      add :expires_at, :utc_datetime, null: false
      add :completed_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:verification_sessions, [:workspace_id])
    create unique_index(:verification_sessions, [:state])
    create index(:verification_sessions, [:expires_at])
  end
end
