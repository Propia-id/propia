defmodule Sovra.Repo.Migrations.CreateCredentialOffers do
  use Ecto.Migration

  def change do
    create table(:credential_offers, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :issuer_id, references(:issuers, type: :binary_id), null: false
      add :schema_id, references(:credential_schemas, type: :binary_id), null: false
      add :holder_did, :string, null: false
      add :pre_authorized_code, :string, null: false
      add :tx_code, :string
      add :access_token, :string
      add :c_nonce, :string
      add :claims, :map
      add :status, :string, null: false, default: "pending"
      add :sd_jwt, :text, null: false
      add :expires_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:credential_offers, [:pre_authorized_code])
    create unique_index(:credential_offers, [:access_token])
    create index(:credential_offers, [:issuer_id])
  end
end
