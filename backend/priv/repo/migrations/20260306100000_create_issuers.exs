defmodule Sovra.Repo.Migrations.CreateIssuers do
  use Ecto.Migration

  def change do
    create table(:issuers, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :eoa_address, :string, null: false
      add :eoa_key_id, :string, null: false
      add :signing_key_id, :string, null: false
      add :signing_public_key_x, :binary, null: false
      add :signing_public_key_y, :binary, null: false
      add :did, :string, null: false
      add :status, :string, null: false, default: "active"

      timestamps(type: :utc_datetime)
    end

    create unique_index(:issuers, [:eoa_address])
    create unique_index(:issuers, [:did])
  end
end
