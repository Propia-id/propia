defmodule Sovra.Repo.Migrations.CreateIssuedCredentials do
  use Ecto.Migration

  def change do
    create table(:issued_credentials, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :issuer_id, references(:issuers, type: :binary_id), null: false
      add :schema_id, references(:credential_schemas, type: :binary_id), null: false
      add :holder_did, :string, null: false
      add :status, :string, null: false, default: "issued"
      add :issued_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:issued_credentials, [:issuer_id, :status])
  end
end
