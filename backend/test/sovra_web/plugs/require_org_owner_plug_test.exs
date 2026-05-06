defmodule SovraWeb.Plugs.RequireOrgOwnerPlugTest do
  use SovraWeb.ConnCase, async: true

  alias Sovra.Accounts.User
  alias Sovra.Organizations
  alias Sovra.Repo
  alias SovraWeb.Plugs.RequireOrgOwnerPlug

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

    conn = conn_for(conn, owner, org.id) |> RequireOrgOwnerPlug.call([])

    refute conn.halted
    assert conn.assigns.current_org_role == "owner"
  end

  test "rejects admin (not owner)", %{conn: conn} do
    owner = user("owner")
    admin = user("admin")

    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{name: "Acme"})

    {:ok, _} = Organizations.add_member(org.id, admin.id, "admin")

    conn = conn_for(conn, admin, org.id) |> RequireOrgOwnerPlug.call([])

    assert conn.halted
    assert conn.status == 403
    assert Jason.decode!(conn.resp_body) == %{"error" => "org_owner_required"}
  end

  test "rejects non-member", %{conn: conn} do
    owner = user("owner")
    stranger = user("stranger")

    {:ok, %{organization: org}} =
      Organizations.create_organization(owner.id, %{name: "Acme"})

    conn = conn_for(conn, stranger, org.id) |> RequireOrgOwnerPlug.call([])

    assert conn.halted
    assert conn.status == 403
  end
end
