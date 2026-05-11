defmodule SovraWeb.Workspaces.WorkspaceMemberControllerTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Auth.UserSession
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces

  defp user(suffix) do
    {:ok, account} =
      User.admin_changeset(%{
        email: "#{suffix}-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    account
  end

  defp setup_env(_) do
    owner = user("owner")

    {:ok, organization} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} =
      Workspaces.create_workspace(organization.id, %{name: "Acme"}, owner.id)

    {:ok, token} = UserSession.create(owner.id, ws.id, owner.is_admin)

    %{workspace: ws, owner: owner, token: token}
  end

  setup :setup_env

  defp authed(conn, token), do: put_req_header(conn, "authorization", "Bearer #{token}")

  test "admin adds a member by email", %{conn: conn, workspace: ws, token: token} do
    new = user("new")

    resp =
      conn
      |> authed(token)
      |> post("/dashboard/workspaces/#{ws.id}/members", %{
        "email" => new.email,
        "role" => "member"
      })
      |> json_response(201)

    assert resp["email"] == new.email
    assert resp["role"] == "member"
    assert {:ok, "member"} = Workspaces.member_role(ws.id, new.id)
  end

  test "admin changes a member's role", %{conn: conn, workspace: ws, token: token} do
    new = user("new")
    {:ok, _} = Workspaces.add_member(ws.id, new.id, "member")

    resp =
      conn
      |> authed(token)
      |> patch("/dashboard/workspaces/#{ws.id}/members/#{new.id}", %{"role" => "admin"})
      |> json_response(200)

    assert resp["role"] == "admin"
  end

  test "last admin can't be demoted (409)", %{
    conn: conn,
    workspace: ws,
    owner: owner,
    token: token
  } do
    conn =
      conn
      |> authed(token)
      |> patch("/dashboard/workspaces/#{ws.id}/members/#{owner.id}", %{"role" => "member"})

    assert json_response(conn, 409) == %{"error" => "last_admin"}
  end

  test "last admin can't be removed (409)", %{
    conn: conn,
    workspace: ws,
    owner: owner,
    token: token
  } do
    conn =
      conn
      |> authed(token)
      |> delete("/dashboard/workspaces/#{ws.id}/members/#{owner.id}")

    assert json_response(conn, 409) == %{"error" => "last_admin"}
  end

  test "plain member cannot add another member", %{conn: conn, workspace: ws} do
    member = user("member")
    {:ok, _} = Workspaces.add_member(ws.id, member.id, "member")
    {:ok, member_token} = UserSession.create(member.id, ws.id, member.is_admin)

    conn =
      conn
      |> authed(member_token)
      |> post("/dashboard/workspaces/#{ws.id}/members", %{
        "email" => "x@example.com",
        "role" => "member"
      })

    assert json_response(conn, 403) == %{"error" => "workspace_admin_required"}
  end
end
