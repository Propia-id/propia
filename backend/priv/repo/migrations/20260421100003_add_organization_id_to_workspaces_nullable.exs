defmodule Sovra.Repo.Migrations.AddOrganizationIdToWorkspacesNullable do
  use Ecto.Migration

  def change do
    alter table(:workspaces) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :restrict)
    end

    create index(:workspaces, [:organization_id])
  end
end
