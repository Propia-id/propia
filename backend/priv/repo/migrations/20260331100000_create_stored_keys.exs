defmodule Sovra.Repo.Migrations.CreateStoredKeys do
  use Ecto.Migration

  def change do
    create table(:stored_keys, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :key_id, :string, null: false
      add :private_key, :binary, null: false
      add :holder_id, :string

      timestamps(type: :utc_datetime)
    end

    create unique_index(:stored_keys, [:key_id])
  end
end
