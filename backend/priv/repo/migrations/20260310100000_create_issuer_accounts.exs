defmodule Sovra.Repo.Migrations.CreateIssuerAccounts do
  use Ecto.Migration

  def change do
    create table(:issuer_accounts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :email, :string, null: false
      add :password_hash, :string, null: false
      add :issuer_id, references(:issuers, type: :binary_id, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:issuer_accounts, [:email])
    create unique_index(:issuer_accounts, [:issuer_id])
  end
end
