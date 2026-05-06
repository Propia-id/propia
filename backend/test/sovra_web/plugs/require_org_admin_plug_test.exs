defmodule SovraWeb.Plugs.RequireOrgAdminPlugTest do
  use SovraWeb.ConnCase, async: true

  alias Sovra.Accounts.User
  alias Sovra.Organizations
  alias Sovra.Repo
  alias SovraWeb.Plugs.RequireOrgAdminPlug

  defp user(suffix) do
    {:ok, account} =
      User.admin_changeset(%{
        email: "#{suffix}-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    account
  end

  defp conn_for(conn, account, org_id) do
    conn
    |> Map.put(:path_params, %{"org_id" => org_id})
    |> assign(:current_user, %{
      user_id: account.id,
      workspace_id: nil,
      is_admin: account.is_admin
    })
  end

  test "allows owner", %{conn: conn} do
    owner = user("owner")

    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{name: "Acme"})

    conn = conn_for(conn, owner, org.id) |> RequireOrgAdminPlug.call([])

    refute conn.halted
    assert conn.assigns.current_org_role == "owner"
  end

  test "allows admin", %{conn: conn} do
    owner = user("owner")
    admin = user("admin")

    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{name: "Acme"})

    {:ok, _} = Organizations.add_member(org.id, admin.id, "admin")

    conn = conn_for(conn, admin, org.id) |> RequireOrgAdminPlug.call([])

    refute conn.halted
    assert conn.assigns.current_org_role == "admin"
  end

  test "rejects plain member", %{conn: conn} do
    owner = user("owner")
    member = user("member")

    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{name: "Acme"})

    {:ok, _} = Organizations.add_member(org.id, member.id, "member")

    conn = conn_for(conn, member, org.id) |> RequireOrgAdminPlug.call([])

    assert conn.halted
    assert conn.status == 403
    assert Jason.decode!(conn.resp_body) == %{"error" => "org_admin_required"}
  end

  test "rejects non-member with 404 (no existence leak)", %{conn: conn} do
    owner = user("owner")
    stranger = user("stranger")

    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{name: "Acme"})

    conn = conn_for(conn, stranger, org.id) |> RequireOrgAdminPlug.call([])

    assert conn.halted
    assert conn.status == 404
    assert Jason.decode!(conn.resp_body) == %{"error" => "organization_not_found"}
  end

  test "rejects platform admin with no org membership (no bypass)", %{conn: conn} do
    owner = user("owner")
    admin = user("platform-admin")

    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{name: "Acme"})

    conn = conn_for(conn, admin, org.id) |> RequireOrgAdminPlug.call([])

    assert conn.halted
    assert conn.status == 404
  end
end
