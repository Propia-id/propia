defmodule Sovra.Repo.Migrations.AddStatusPurposeToCredentialOffers do
  use Ecto.Migration

  @index_name :credential_offers_status_index_purpose_idx

  def change do
    alter table(:credential_offers) do
      add :status_purpose, :string, default: "revocation", null: false
    end

    create unique_index(
             :credential_offers,
             [:issuer_id, :status_list_index, :status_purpose],
             name: @index_name
           )
  end
end
