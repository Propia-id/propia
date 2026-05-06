defmodule SovraWeb.Plugs.ApiKeyPlugTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKeys
  alias SovraWeb.Plugs.ApiKeyPlug

  defp setup_workspace_and_key(_) do
    {:ok, user} =
      User.admin_changeset(%{
        email: "u-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, user.id)
    {:ok, %{api_key: plaintext, record: rec}} = ApiKeys.create_api_key(ws.id, "Prod")
    %{workspace: ws, api_key: plaintext, record: rec}
  end

  setup :setup_workspace_and_key

  test "401 when header missing", %{conn: conn} do
    conn = ApiKeyPlug.call(conn, [])
    assert conn.halted
    assert conn.status == 401
    assert Jason.decode!(conn.resp_body) == %{"error" => "invalid_api_key"}
  end

  test "401 on unknown key", %{conn: conn} do
    conn =
      conn
      |> put_req_header("authorization", "Bearer sovra_sk_bogus")
      |> ApiKeyPlug.call([])

    assert conn.halted
    assert conn.status == 401
  end

  test "401 on revoked key", %{conn: conn, api_key: key, record: rec} do
    {:ok, _} = ApiKeys.revoke_api_key(rec)

    conn =
      conn
      |> put_req_header("authorization", "Bearer #{key}")
      |> ApiKeyPlug.call([])

    assert conn.halted
    assert conn.status == 401
  end

  test "valid key assigns workspace + api_key_id", %{
    conn: conn,
    workspace: ws,
    api_key: key,
    record: rec
  } do
    conn =
      conn
      |> put_req_header("authorization", "Bearer #{key}")
      |> ApiKeyPlug.call([])

    refute conn.halted
    assert conn.assigns.current_workspace_id == ws.id
    assert conn.assigns.current_api_key_id == rec.id
    assert conn.assigns.current_auth_method == :api_key
  end
end
