defmodule Sovra.Repo.Migrations.AddStatusListIndexToCredentialOffers do
  use Ecto.Migration

  def change do
    alter table(:credential_offers) do
      add :status_list_index, :integer
    end
  end
end
