defmodule SovraWeb.Plugs.RequireActiveTenantPlugTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Organizations
  alias Sovra.Workspaces.Workspace
  alias SovraWeb.Plugs.RequireActiveTenantPlug

  defp call(conn, workspace_id) do
    conn
    |> assign(:current_workspace_id, workspace_id)
    |> RequireActiveTenantPlug.call([])
  end

  defp set_status(ws, status) do
    {:ok, ws} = ws |> Workspace.status_changeset(status) |> Sovra.Repo.update()
    ws
  end

  test "passes an active workspace in an active organization", %{conn: conn} do
    %{workspace: ws} = fixture_workspace()

    refute call(conn, ws.id).halted
  end

  for status <- ~w(suspended deactivated) do
    test "refuses a #{status} workspace", %{conn: conn} do
      %{workspace: ws} = fixture_workspace()
      set_status(ws, unquote(status))

      conn = call(conn, ws.id)

      assert conn.halted
      assert json_response(conn, 403) == %{"error" => "workspace_inactive"}
    end
  end

  test "refuses an active workspace in a deactivated organization", %{conn: conn} do
    %{workspace: ws, org: org} = fixture_workspace()
    {:ok, _} = Organizations.deactivate_organization(org)

    conn = call(conn, ws.id)

    assert conn.halted
    assert json_response(conn, 403) == %{"error" => "organization_inactive"}
  end

  test "refuses a workspace that does not exist", %{conn: conn} do
    conn = call(conn, Ecto.UUID.generate())

    assert conn.halted
    assert json_response(conn, 403) == %{"error" => "workspace_not_found"}
  end

  test "refuses a session with no workspace", %{conn: conn} do
    conn = call(conn, nil)

    assert conn.halted
    assert json_response(conn, 403) == %{"error" => "no_workspace"}
  end
end
