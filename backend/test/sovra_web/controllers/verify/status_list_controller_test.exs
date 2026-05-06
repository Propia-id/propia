defmodule SovraWeb.Verify.StatusListControllerTest do
  @moduledoc """
  Covers the public status-list endpoint at
  `GET /api/v1/status/:issuer_did/:purpose`. The 200 happy path requires
  an Ethereum read for the bitmap and is exercised in integration tests;
  this file pins down the input validation and lookup paths so a stale
  module alias like `Sovra.Issuer.IssuerRecord` can't slip through again.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces

  defp create_workspace do
    {:ok, account} =
      User.admin_changeset(%{
        email: "user-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Issuer"}, account.id)
    ws
  end

  test "400 on unknown purpose", %{conn: conn} do
    ws = create_workspace()

    resp =
      conn
      |> get("/api/v1/status/#{URI.encode(ws.did)}/garbage")
      |> json_response(400)

    assert resp == %{"error" => "invalid_purpose"}
  end

  test "404 when no workspace has that DID", %{conn: conn} do
    resp =
      conn
      |> get("/api/v1/status/did:sovra:0xdoesnotexist/revocation")
      |> json_response(404)

    assert resp == %{"error" => "issuer_not_found"}
  end

  test "404 when the URL slot is a workspace UUID instead of a DID", %{conn: conn} do
    ws = create_workspace()

    resp =
      conn
      |> get("/api/v1/status/#{ws.id}/revocation")
      |> json_response(404)

    assert resp == %{"error" => "issuer_not_found"}
  end
end
