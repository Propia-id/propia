defmodule Sovra.Repo.Migrations.CreateOrganizations do
  use Ecto.Migration

  def change do
    create table(:organizations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :string, null: false
      add :logo_url, :string
      add :website, :string
      add :status, :string, null: false, default: "active"

      timestamps(type: :utc_datetime)
    end
  end
end
