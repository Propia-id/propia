defmodule Sovra.Repo.Migrations.BackfillWorkspaceMembers do
  use Ecto.Migration

  import Ecto.Query

  alias Sovra.Repo

  def up do
    Repo.transaction(fn ->
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      rows =
        from(a in "issuer_accounts",
          where: not is_nil(a.workspace_id),
          select: %{workspace_id: a.workspace_id, user_id: a.id}
        )
        |> Repo.all()

      entries =
        Enum.map(rows, fn row ->
          %{
            workspace_id: row.workspace_id,
            user_id: row.user_id,
            role: "admin",
            inserted_at: now,
            updated_at: now
          }
        end)

      if entries != [] do
        Repo.insert_all("workspace_members", entries, on_conflict: :nothing)
      end
    end)
  end

  def down do
    execute "DELETE FROM workspace_members"
  end
end
