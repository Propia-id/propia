defmodule SovraWeb.Workspaces.WorkspaceControllerTest do
  use SovraWeb.ConnCase, async: false

  import Sovra.LogHelpers

  alias Sovra.Auth.UserSession
  alias Sovra.Organizations
  alias Sovra.Workspaces

  defp user(suffix), do: fixture_user("#{suffix}-#{System.unique_integer([:positive])}")

  defp org(suffix \\ "#{System.unique_integer([:positive])}"), do: fixture_org(suffix)

  defp org_with_owner(owner) do
    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{
        name: "Org #{System.unique_integer([:positive])}"
      })

    org
  end

  defp create_workspace(owner \\ nil) do
    owner = owner || user("owner")
    org = org_with_owner(owner)
    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)
    %{workspace: provision_workspace(ws), owner: owner, org: org}
  end

  defp authed(conn, account, workspace_id \\ nil) do
    {:ok, token} = UserSession.create(account.id, workspace_id, account.is_admin)
    put_req_header(conn, "authorization", "Bearer #{token}")
  end

  describe "POST /dashboard/organizations/:org_id/workspaces" do
    test "creates a workspace + caller is admin", %{conn: conn} do
      owner = user("owner")
      organization = org_with_owner(owner)

      resp =
        conn
        |> authed(owner)
        |> post("/dashboard/organizations/#{organization.id}/workspaces", %{"name" => "Fresh"})
        |> json_response(201)

      assert resp["workspace"]["name"] == "Fresh"
      assert resp["workspace"]["role"] == "admin"
      assert resp["workspace"]["provisioning_status"] == "pending"
      assert resp["workspace"]["did"] == nil
      refute Map.has_key?(resp, "webhook_secret")

      assert {:ok, "admin"} = Workspaces.member_role(resp["workspace"]["id"], owner.id)
    end

    test "404 when caller is not a member of the organization", %{conn: conn} do
      attacker = user("attacker")
      victim_org = org()

      resp =
        conn
        |> authed(attacker)
        |> post("/dashboard/organizations/#{victim_org.id}/workspaces", %{"name" => "Hijack"})
        |> json_response(404)

      assert resp["error"] == "organization_not_found"
    end

    test "403 when caller is a member but not an org admin", %{conn: conn} do
      owner = user("owner")
      organization = org_with_owner(owner)
      member = user("member")
      {:ok, _} = Organizations.add_member(organization.id, member.id, "member")

      resp =
        conn
        |> authed(member)
        |> post("/dashboard/organizations/#{organization.id}/workspaces", %{"name" => "Nope"})
        |> json_response(403)

      assert resp["error"] == "org_admin_required"
    end

    test "401 without session", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "application/json")
        |> post("/dashboard/organizations/#{Ecto.UUID.generate()}/workspaces", %{"name" => "X"})

      assert json_response(conn, 401)
    end
  end

  describe "GET /dashboard/organizations/:org_id/workspaces" do
    test "org admin sees every workspace in the org regardless of membership", %{conn: conn} do
      owner = user("owner")
      organization = org_with_owner(owner)
      stranger = user("stranger")

      {:ok, %{workspace: ws_a}} =
        Workspaces.create_workspace(organization.id, %{name: "A"}, owner.id)

      {:ok, %{workspace: ws_b}} =
        Workspaces.create_workspace(organization.id, %{name: "B"}, stranger.id)

      resp =
        conn
        |> authed(owner)
        |> get("/dashboard/organizations/#{organization.id}/workspaces")
        |> json_response(200)

      ids = Enum.map(resp["workspaces"], & &1["id"]) |> Enum.sort()
      assert ids == Enum.sort([ws_a.id, ws_b.id])
    end

    test "404 when caller is not a member", %{conn: conn} do
      attacker = user("attacker")
      victim_org = org()

      resp =
        conn
        |> authed(attacker)
        |> get("/dashboard/organizations/#{victim_org.id}/workspaces")
        |> json_response(404)

      assert resp["error"] == "organization_not_found"
    end

    test "403 when caller is a member but not an org admin", %{conn: conn} do
      owner = user("owner")
      organization = org_with_owner(owner)
      member = user("member")
      {:ok, _} = Organizations.add_member(organization.id, member.id, "member")

      resp =
        conn
        |> authed(member)
        |> get("/dashboard/organizations/#{organization.id}/workspaces")
        |> json_response(403)

      assert resp["error"] == "org_admin_required"
    end
  end

  describe "GET /dashboard/workspaces" do
    test "returns only workspaces the caller belongs to", %{conn: conn} do
      %{workspace: ws_a, owner: owner_a} = create_workspace()
      %{workspace: _ws_b} = create_workspace()

      resp =
        conn
        |> authed(owner_a, ws_a.id)
        |> get("/dashboard/workspaces")
        |> json_response(200)

      ids = Enum.map(resp["workspaces"], & &1["id"])
      assert ids == [ws_a.id]
    end
  end

  describe "PATCH /dashboard/workspaces/:workspace_id" do
    test "admin updates the name", %{conn: conn} do
      %{workspace: ws, owner: owner} = create_workspace()

      resp =
        conn
        |> authed(owner, ws.id)
        |> patch("/dashboard/workspaces/#{ws.id}", %{"name" => "Renamed"})
        |> json_response(200)

      assert resp["name"] == "Renamed"
    end

    test "plain member returns 403", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      member = user("member")
      {:ok, _} = Workspaces.add_member(ws.id, member.id, "member")

      conn =
        conn
        |> authed(member, ws.id)
        |> patch("/dashboard/workspaces/#{ws.id}", %{"name" => "Nope"})

      assert json_response(conn, 403) == %{"error" => "workspace_admin_required"}
    end
  end

  describe "POST /dashboard/workspaces/:workspace_id/switch" do
    test "mints a new JWT and revokes the previous one", %{conn: conn} do
      owner = user("owner")
      organization = org()

      {:ok, %{workspace: ws_a}} =
        Workspaces.create_workspace(organization.id, %{name: "A"}, owner.id)

      {:ok, %{workspace: ws_b}} =
        Workspaces.create_workspace(organization.id, %{name: "B"}, owner.id)

      conn =
        conn
        |> authed(owner, ws_a.id)
        |> post("/dashboard/workspaces/#{ws_b.id}/switch")

      assert json_response(conn, 200)["id"] == ws_b.id

      # The new session cookie must be scoped to /dashboard so subsequent
      # dashboard requests carry it.
      assert %{path: "/dashboard"} = conn.resp_cookies["session"]
    end

    # The revoke of the old session is the last thing to touch the context.
    test "logs the workspace switched to, not the one left", %{conn: conn} do
      owner = user("owner")
      organization = org()

      {:ok, %{workspace: ws_a}} =
        Workspaces.create_workspace(organization.id, %{name: "A"}, owner.id)

      {:ok, %{workspace: ws_b}} =
        Workspaces.create_workspace(organization.id, %{name: "B"}, owner.id)

      {conn, events} =
        capture_events(fn ->
          conn
          |> authed(owner, ws_a.id)
          |> post("/dashboard/workspaces/#{ws_b.id}/switch")
        end)

      assert conn.status == 200

      request = assert_event(events, "http.request")
      assert request.metadata[:workspace_id] == ws_b.id
      assert request.metadata[:user_id] == owner.id
    end

    test "non-member 403", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      stranger = user("stranger")
      other_org = org()

      {:ok, %{workspace: stranger_ws}} =
        Workspaces.create_workspace(other_org.id, %{name: "Other"}, stranger.id)

      conn =
        conn
        |> authed(stranger, stranger_ws.id)
        |> post("/dashboard/workspaces/#{ws.id}/switch")

      assert json_response(conn, 403)
    end
  end

  describe "POST /dashboard/organizations/:org_id/workspaces/:workspace_id/retry_provisioning" do
    test "org admin retries a failed workspace", %{conn: conn} do
      %{workspace: ws, owner: owner, org: organization} = create_workspace()
      {:ok, _} = Workspaces.mark_provisioning_failed(ws.id, "boom")

      resp =
        conn
        |> authed(owner)
        |> post(
          "/dashboard/organizations/#{organization.id}/workspaces/#{ws.id}/retry_provisioning"
        )
        |> json_response(200)

      assert resp["id"] == ws.id
      assert resp["provisioning_status"] == "pending"
      assert resp["provisioning_error"] == nil
    end

    test "409 when workspace is already pending", %{conn: conn} do
      owner = user("owner")
      organization = org_with_owner(owner)

      {:ok, %{workspace: ws}} =
        Workspaces.create_workspace(organization.id, %{name: "Pending"}, owner.id)

      resp =
        conn
        |> authed(owner)
        |> post(
          "/dashboard/organizations/#{organization.id}/workspaces/#{ws.id}/retry_provisioning"
        )
        |> json_response(409)

      assert resp["error"] == "already_pending"
    end

    test "409 when workspace is already provisioned", %{conn: conn} do
      %{workspace: ws, owner: owner, org: organization} = create_workspace()

      resp =
        conn
        |> authed(owner)
        |> post(
          "/dashboard/organizations/#{organization.id}/workspaces/#{ws.id}/retry_provisioning"
        )
        |> json_response(409)

      assert resp["error"] == "already_provisioned"
    end

    test "404 when the workspace belongs to a different organization", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      foreigner = user("foreigner")
      other_org = org_with_owner(foreigner)

      resp =
        conn
        |> authed(foreigner)
        |> post("/dashboard/organizations/#{other_org.id}/workspaces/#{ws.id}/retry_provisioning")
        |> json_response(404)

      assert resp["error"] == "workspace_not_found"
    end

    test "403 when caller is a workspace admin but not org admin", %{conn: conn} do
      owner = user("owner")
      organization = org_with_owner(owner)

      {:ok, %{workspace: ws}} =
        Workspaces.create_workspace(organization.id, %{name: "W"}, owner.id)

      ws = provision_workspace(ws)
      {:ok, _} = Workspaces.mark_provisioning_failed(ws.id, "boom")

      ws_admin = user("ws_admin")
      {:ok, _} = Organizations.add_member(organization.id, ws_admin.id, "member")
      {:ok, _} = Workspaces.add_member(ws.id, ws_admin.id, "admin")

      resp =
        conn
        |> authed(ws_admin)
        |> post(
          "/dashboard/organizations/#{organization.id}/workspaces/#{ws.id}/retry_provisioning"
        )
        |> json_response(403)

      assert resp["error"] == "org_admin_required"
    end
  end
end
