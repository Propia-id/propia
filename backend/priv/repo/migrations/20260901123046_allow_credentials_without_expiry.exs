defmodule Sovra.Repo.Migrations.AllowCredentialsWithoutExpiry do
  use Ecto.Migration

  # `credential_offers.expires_at` stays NOT NULL: that is the QR's 24h
  # validity, not the credential's.
  def change do
    alter table(:credential_schemas) do
      modify :validity_period, :string, null: true, from: {:string, null: false}
    end

    alter table(:issued_credentials) do
      modify :expires_at, :utc_datetime, null: true, from: {:utc_datetime, null: false}
    end
  end
end
