defmodule Sovra.Repo.Migrations.AddStatusListIndexToIssuedCredentials do
  use Ecto.Migration

  def change do
    alter table(:issued_credentials) do
      add :status_list_index, :integer
      add :status_purpose, :string, default: "revocation"
    end

    create unique_index(:issued_credentials, [:issuer_id, :status_list_index, :status_purpose])
  end
end
