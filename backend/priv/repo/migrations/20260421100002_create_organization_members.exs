defmodule Sovra.Repo.Migrations.CreateOrganizationMembers do
  use Ecto.Migration

  def change do
    create table(:organization_members, primary_key: false) do
      add :organization_id,
          references(:organizations, type: :binary_id, on_delete: :delete_all),
          null: false,
          primary_key: true

      add :user_id,
          references(:issuer_accounts, type: :binary_id, on_delete: :delete_all),
          null: false,
          primary_key: true

      add :role, :string, null: false, default: "member"

      timestamps(type: :utc_datetime)
    end

    create index(:organization_members, [:user_id])
  end
end
