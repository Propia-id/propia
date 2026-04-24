defmodule Sovra.Repo.Migrations.BackfillWorkspaceOrganizations do
  use Ecto.Migration

  import Ecto.Query

  alias Sovra.Repo

  def up do
    Repo.transaction(fn ->
      workspaces =
        from(w in "workspaces",
          where: is_nil(w.organization_id),
          select: %{id: w.id, name: w.name}
        )
        |> Repo.all()

      Enum.each(workspaces, fn workspace ->
        org_id = Ecto.UUID.generate()
        now = DateTime.utc_now() |> DateTime.truncate(:second)

        Repo.insert_all("organizations", [
          %{
            id: Ecto.UUID.dump!(org_id),
            name: workspace.name,
            logo_url: nil,
            website: nil,
            status: "active",
            inserted_at: now,
            updated_at: now
          }
        ])

        from(w in "workspaces", where: w.id == ^workspace.id)
        |> Repo.update_all(set: [organization_id: Ecto.UUID.dump!(org_id)])

        owner_account_id =
          from(a in "issuer_accounts",
            where: a.workspace_id == ^workspace.id,
            select: a.id,
            limit: 1
          )
          |> Repo.one()

        if owner_account_id do
          Repo.insert_all("organization_members", [
            %{
              organization_id: Ecto.UUID.dump!(org_id),
              user_id: owner_account_id,
              role: "owner",
              inserted_at: now,
              updated_at: now
            }
          ])
        end
      end)
    end)
  end

  def down do
    execute "UPDATE workspaces SET organization_id = NULL"
    execute "DELETE FROM organization_members"
    execute "DELETE FROM organizations"
  end
end
