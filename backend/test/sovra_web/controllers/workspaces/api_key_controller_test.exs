defmodule SovraWeb.Workspaces.ApiKeyControllerTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Auth.UserSession
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKeys

  defp setup_env(_) do
    {:ok, owner} =
      User.admin_changeset(%{
        email: "o-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

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

  test "admin creates + lists + revokes API keys", %{conn: conn, workspace: ws, token: token} do
    create_resp =
      conn
      |> authed(token)
      |> post("/api/v1/workspaces/#{ws.id}/api_keys", %{"name" => "Prod"})
      |> json_response(201)

    assert String.starts_with?(create_resp["api_key"], "sovra_sk_")
    assert create_resp["record"]["name"] == "Prod"
    key_id = create_resp["record"]["id"]

    list_resp =
      conn
      |> authed(token)
      |> get("/api/v1/workspaces/#{ws.id}/api_keys")
      |> json_response(200)

    [listed] = list_resp["api_keys"]
    assert listed["id"] == key_id
    refute listed["api_key"]
    refute listed["api_key_hash"]

    revoke_resp =
      conn
      |> authed(token)
      |> post("/api/v1/workspaces/#{ws.id}/api_keys/#{key_id}/revoke")
      |> json_response(200)

    assert revoke_resp["revoked_at"]
  end

  test "plain member cannot create keys", %{conn: conn, workspace: ws} do
    {:ok, member} =
      User.admin_changeset(%{
        email: "m-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    {:ok, _} = Workspaces.add_member(ws.id, member.id, "member")
    {:ok, member_token} = UserSession.create(member.id, ws.id, member.is_admin)

    conn =
      conn
      |> authed(member_token)
      |> post("/api/v1/workspaces/#{ws.id}/api_keys", %{"name" => "Try"})

    assert json_response(conn, 403) == %{"error" => "workspace_admin_required"}
  end

  test "revoked key is rejected by ApiKeyPlug against credential-offer", %{
    conn: conn,
    workspace: ws,
    token: token
  } do
    resp =
      conn
      |> authed(token)
      |> post("/api/v1/workspaces/#{ws.id}/api_keys", %{"name" => "Tmp"})
      |> json_response(201)

    plaintext = resp["api_key"]
    key_id = resp["record"]["id"]

    conn
    |> authed(token)
    |> post("/api/v1/workspaces/#{ws.id}/api_keys/#{key_id}/revoke")

    reject_conn =
      build_conn()
      |> put_req_header("authorization", "Bearer #{plaintext}")
      |> post("/api/v1/issuer/credential-offer", %{"schema_id" => "x"})

    assert json_response(reject_conn, 401) == %{"error" => "invalid_api_key"}

    # Leave `ApiKeys` referenced to keep the alias meaningful.
    _ = ApiKeys
  end
end
