defmodule Sovra.Repo.Migrations.RequireWorkspaceOrganization do
  use Ecto.Migration

  def up do
    alter table(:workspaces) do
      modify :organization_id, :binary_id, null: false
    end
  end

  def down do
    alter table(:workspaces) do
      modify :organization_id, :binary_id, null: true
    end
  end
end
