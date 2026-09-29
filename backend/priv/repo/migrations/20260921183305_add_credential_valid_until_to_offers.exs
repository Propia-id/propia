defmodule Sovra.Repo.Migrations.AddCredentialValidUntilToOffers do
  use Ecto.Migration

  # The issuer's custom expiration for the credential this offer will become.
  #
  # Deliberately not named `expires_at`: that column already exists on this
  # table and means the offer's own 24h pickup window, an unrelated instant.
  # Naming both the same thing would invite reading one for the other.
  #
  # Nullable, and null is the norm — it means "derive expiry from the schema's
  # validity_period at redemption", which is what every existing row does and
  # what every request that omits `valid_until` keeps doing.
  def change do
    alter table(:credential_offers) do
      add :credential_valid_until, :utc_datetime
    end
  end
end
