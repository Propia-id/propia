defmodule SovraWeb.Issuer.AdminCredentialStatusTest do
  @moduledoc """
  Covers `POST /api/v1/issuer/admin/credentials/:id/revoke` and `/suspend`.
  These are workspace-admin-only; plain members get 403.
  """
  use SovraWeb.ConnCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Auth.IssuerSession
  alias Sovra.Issuer
  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Organizations.Organization
  alias Sovra.Webhooks.DeliveryJob
  alias Sovra.Workspaces

  defp user(suffix) do
    {:ok, account} =
      IssuerAccount.admin_changeset(%{
        email: "#{suffix}-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    account
  end

  defp org do
    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    org
  end

  defp setup_workspace_with_credential do
    owner = user("owner")
    org = org()
    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)

    {:ok, schema} =
      Issuer.create_schema(ws.id, %{
        schema_id: "s-#{System.unique_integer([:positive])}",
        credential_type: "TestCredential",
        name: "Test",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    cred_changeset =
      Sovra.Issuer.IssuedCredential.create_changeset(%{
        issuer_id: ws.id,
        schema_id: schema.id,
        holder_did: "did:sovra:0xholder",
        issued_at: now,
        expires_at: DateTime.add(now, 86_400, :second)
      })

    {:ok, cred} = Sovra.Repo.insert(cred_changeset)

    %{workspace: ws, owner: owner, credential: cred}
  end

  defp authed(conn, user, workspace_id),
    do:
      (
        {:ok, token} = IssuerSession.create(user.id, workspace_id, "issuer")
        put_req_header(conn, "authorization", "Bearer #{token}")
      )

  test "admin revokes → status becomes revoked and webhook enqueued", %{conn: conn} do
    %{workspace: ws, owner: owner, credential: cred} = setup_workspace_with_credential()

    resp =
      conn
      |> authed(owner, ws.id)
      |> post("/api/v1/issuer/admin/credentials/#{cred.id}/revoke")
      |> json_response(200)

    assert resp["id"] == cred.id
    assert resp["status"] == "revoked"

    assert_enqueued(worker: DeliveryJob, args: %{"event" => "credential.revoked"})
  end

  test "admin suspends → status becomes suspended and webhook enqueued", %{conn: conn} do
    %{workspace: ws, owner: owner, credential: cred} = setup_workspace_with_credential()

    resp =
      conn
      |> authed(owner, ws.id)
      |> post("/api/v1/issuer/admin/credentials/#{cred.id}/suspend")
      |> json_response(200)

    assert resp["status"] == "suspended"

    assert_enqueued(worker: DeliveryJob, args: %{"event" => "credential.suspended"})
  end

  test "plain member gets 403", %{conn: conn} do
    %{workspace: ws, credential: cred} = setup_workspace_with_credential()
    member = user("member")
    {:ok, _} = Workspaces.add_member(ws.id, member.id, "member")

    conn =
      conn
      |> authed(member, ws.id)
      |> post("/api/v1/issuer/admin/credentials/#{cred.id}/revoke")

    assert json_response(conn, 403) == %{"error" => "workspace_admin_required"}
  end

  test "credential from another workspace returns 404", %{conn: conn} do
    %{workspace: ws_a, owner: owner_a} = setup_workspace_with_credential()
    %{credential: cred_b} = setup_workspace_with_credential()

    conn =
      conn
      |> authed(owner_a, ws_a.id)
      |> post("/api/v1/issuer/admin/credentials/#{cred_b.id}/revoke")

    assert json_response(conn, 404) == %{"error" => "credential_not_found"}
  end
end
