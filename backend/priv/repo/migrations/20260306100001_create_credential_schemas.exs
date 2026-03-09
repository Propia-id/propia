defmodule Sovra.Repo.Migrations.CreateCredentialSchemas do
  use Ecto.Migration

  def change do
    create table(:credential_schemas, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :schema_id, :string, null: false
      add :issuer_id, references(:issuers, type: :binary_id), null: false
      add :credential_type, :string, null: false
      add :name, :string, null: false
      add :claims, {:array, :map}, null: false
      add :validity_period, :string, null: false
      add :version, :integer, null: false, default: 1

      timestamps(type: :utc_datetime)
    end

    create unique_index(:credential_schemas, [:issuer_id, :schema_id])
    create index(:credential_schemas, [:issuer_id])
  end
end
