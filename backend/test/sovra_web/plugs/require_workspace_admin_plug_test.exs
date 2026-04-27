defmodule SovraWeb.Plugs.RequireWorkspaceAdminPlugTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias SovraWeb.Plugs.RequireWorkspaceAdminPlug

  defp user(suffix) do
    {:ok, account} =
      IssuerAccount.admin_changeset(%{
        email: "#{suffix}-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    account
  end

  defp setup_workspace do
    owner = user("owner")

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)
    %{workspace: ws, owner: owner}
  end

  defp conn_for(conn, account, workspace_id) do
    conn
    |> Map.put(:path_params, %{"workspace_id" => workspace_id})
    |> assign(:current_issuer_account, %{
      account_id: account.id,
      workspace_id: workspace_id,
      role: account.role
    })
  end

  test "allows workspace admin", %{conn: conn} do
    %{workspace: ws, owner: owner} = setup_workspace()
    conn = conn_for(conn, owner, ws.id) |> RequireWorkspaceAdminPlug.call([])

    refute conn.halted
    assert conn.assigns.current_workspace_role == "admin"
  end

  test "rejects plain member", %{conn: conn} do
    %{workspace: ws} = setup_workspace()
    member = user("member")
    {:ok, _} = Workspaces.add_member(ws.id, member.id, "member")

    conn = conn_for(conn, member, ws.id) |> RequireWorkspaceAdminPlug.call([])

    assert conn.halted
    assert conn.status == 403
    assert Jason.decode!(conn.resp_body) == %{"error" => "workspace_admin_required"}
  end

  test "rejects non-member", %{conn: conn} do
    %{workspace: ws} = setup_workspace()
    stranger = user("stranger")

    conn = conn_for(conn, stranger, ws.id) |> RequireWorkspaceAdminPlug.call([])

    assert conn.halted
    assert conn.status == 403
  end

  test "rejects platform super-admin who isn't a workspace member", %{conn: conn} do
    %{workspace: ws} = setup_workspace()
    admin = user("platform-admin")
    {:ok, admin} = admin |> Ecto.Changeset.change(role: "admin") |> Sovra.Repo.update()

    conn = conn_for(conn, admin, ws.id) |> RequireWorkspaceAdminPlug.call([])

    assert conn.halted
    assert conn.status == 403
  end
end
