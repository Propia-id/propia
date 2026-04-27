defmodule Sovra.Repo.Migrations.CreateWorkspaceMembers do
  use Ecto.Migration

  def change do
    create table(:workspace_members, primary_key: false) do
      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          null: false,
          primary_key: true

      add :user_id,
          references(:issuer_accounts, type: :binary_id, on_delete: :delete_all),
          null: false,
          primary_key: true

      add :role, :string, null: false, default: "member"

      timestamps(type: :utc_datetime)
    end

    create index(:workspace_members, [:user_id])
  end
end
