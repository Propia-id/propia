defmodule SovraWeb.Issuer.OfferControllerTest do
  use SovraWeb.ConnCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Auth.IssuerSession
  alias Sovra.Issuer
  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKeys

  defp create_user do
    {:ok, account} =
      IssuerAccount.admin_changeset(%{
        email: "user-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    account
  end

  defp create_workspace do
    user = create_user()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, user.id)
    %{workspace: ws, user: user}
  end

  defp create_schema(workspace_id) do
    {:ok, schema} =
      Issuer.create_schema(workspace_id, %{
        schema_id: "test-#{System.unique_integer([:positive])}",
        credential_type: "TestCredential",
        name: "Test",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    schema
  end

  describe "POST /api/v1/issuer/admin/offers (JWT path)" do
    test "201 with the unified response shape", %{conn: conn} do
      %{workspace: ws, user: user} = create_workspace()
      schema = create_schema(ws.id)

      {:ok, token} = IssuerSession.create(user.id, ws.id, "issuer")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> post("/api/v1/issuer/admin/offers", %{
          "schema_id" => schema.schema_id,
          "claims" => %{"name" => "Alice"}
        })
        |> json_response(201)

      assert resp["credential_id"]
      assert resp["offer_uri"]
      assert resp["pre_authorized_code"]
      assert resp["expires_at"]
    end
  end

  describe "POST /api/v1/issuer/credential-offer (API key path)" do
    test "201 with the unified response shape", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      schema = create_schema(ws.id)
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/issuer/credential-offer", %{
          "schema_id" => schema.schema_id,
          "claims" => %{"name" => "Alice"}
        })
        |> json_response(201)

      assert resp["credential_id"]
      assert resp["offer_uri"]
    end

    test "401 without API key", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "application/json")
        |> post("/api/v1/issuer/credential-offer", %{"schema_id" => "x"})

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "401 with unknown API key", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer sovra_sk_not-real")
        |> post("/api/v1/issuer/credential-offer", %{"schema_id" => "x"})

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "401 with revoked API key", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key, record: rec}} = ApiKeys.create_api_key(ws.id, "Tmp")
      {:ok, _} = ApiKeys.revoke_api_key(rec)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/issuer/credential-offer", %{"schema_id" => "x"})

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "API key from workspace A can't create offer using schema from workspace B", %{
      conn: conn
    } do
      %{workspace: ws_a} = create_workspace()
      %{workspace: ws_b} = create_workspace()
      schema_b = create_schema(ws_b.id)
      {:ok, %{api_key: key_a}} = ApiKeys.create_api_key(ws_a.id, "A")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key_a}")
        |> post("/api/v1/issuer/credential-offer", %{
          "schema_id" => schema_b.schema_id,
          "claims" => %{"name" => "Alice"}
        })
        |> json_response(404)

      assert resp["error"] == "schema_not_found"
    end
  end
end
