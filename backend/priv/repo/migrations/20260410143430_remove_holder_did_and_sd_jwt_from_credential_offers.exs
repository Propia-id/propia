defmodule Sovra.Repo.Migrations.RemoveHolderDidAndSdJwtFromCredentialOffers do
  use Ecto.Migration

  def up do
    alter table(:credential_offers) do
      remove :holder_did
      remove :sd_jwt
    end
  end

  def down do
    alter table(:credential_offers) do
      add :holder_did, :string
      add :sd_jwt, :text
    end
  end
end
