defmodule Sovra.Repo.Migrations.CreateStatusLists do
  use Ecto.Migration

  import Ecto.Query, only: [from: 2]

  alias Sovra.Repo

  @initial_width 17
  @purposes ~w(revocation suspension)

  def up do
    create table(:status_lists, primary_key: false) do
      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          null: false,
          primary_key: true

      add :status_purpose, :string, null: false, primary_key: true
      add :width, :integer, null: false, default: @initial_width

      timestamps(type: :utc_datetime)
    end

    flush()

    workspace_ids = from(w in "workspaces", select: w.id) |> Repo.all()

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    rows =
      for id <- workspace_ids,
          purpose <- @purposes,
          do: %{
            workspace_id: id,
            status_purpose: purpose,
            width: @initial_width,
            inserted_at: now,
            updated_at: now
          }

    if rows != [] do
      Repo.insert_all("status_lists", rows)
    end
  end

  def down do
    drop table(:status_lists)
  end
end
