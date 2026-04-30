defmodule Sovra.Repo.Migrations.CreateCredentialDesigns do
  use Ecto.Migration

  def change do
    create table(:credential_designs, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :credential_schema_id,
          references(:credential_schemas, type: :binary_id, on_delete: :delete_all),
          null: false

      add :name, :string, null: false
      add :description, :string
      add :display, :map, null: false, default: %{}
      add :styles, :map, null: false, default: %{}
      add :back, :map
      add :version, :integer, null: false, default: 1

      timestamps(type: :utc_datetime)
    end

    create unique_index(:credential_designs, [:credential_schema_id])
  end
end
