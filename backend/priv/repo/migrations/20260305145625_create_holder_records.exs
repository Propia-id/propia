defmodule Sovra.Repo.Migrations.CreateHolderRecords do
  use Ecto.Migration

  def change do
    create table(:holder_records, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :sovra_address, :string, null: false
      add :server_key_id, :string, null: false
      add :server_public_key_x, :binary, null: false
      add :server_public_key_y, :binary, null: false
      add :oauth_provider, :string, null: false
      add :oauth_subject, :string, null: false
      add :status, :string, null: false, default: "active"

      timestamps(type: :utc_datetime)
    end

    create unique_index(:holder_records, [:sovra_address])
    create unique_index(:holder_records, [:oauth_provider, :oauth_subject])
    create index(:holder_records, [:server_key_id])
  end
end
