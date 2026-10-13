defmodule SovraWeb.Issuer.ApiSchemaTest do
  @moduledoc """
  Covers the API-key-authenticated schema surface used by external
  integrators:

      POST   /api/v1/issuer/schemas
      GET    /api/v1/issuer/schemas
      PUT    /api/v1/issuer/schemas/:schema_id
      DELETE /api/v1/issuer/schemas/:id

  The same controller actions back the dashboard mount under
  `/dashboard/issuer/schemas`. Both pipelines resolve the tenant through
  `conn.assigns.current_workspace_id`, so the cross-workspace tests here are
  what keep the API-key mount from reading another workspace's schemas.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Issuer
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKeys

  defp setup_workspace do
    {:ok, owner} =
      User.admin_changeset(%{
        email: "owner-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)
    ws = provision_workspace(ws)
    {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

    %{workspace: ws, api_key: key}
  end

  defp create_schema(workspace_id, overrides \\ %{}) do
    attrs =
      Map.merge(
        %{
          schema_id: "s-#{System.unique_integer([:positive])}",
          credential_type: "TestCredential",
          name: "Test",
          claims: [
            %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
          ],
          validity_period: "1y"
        },
        overrides
      )

    {:ok, schema} = Issuer.create_schema(workspace_id, attrs)
    schema
  end

  defp authed(conn, key), do: put_req_header(conn, "authorization", "Bearer #{key}")

  defp claims_param,
    do: [%{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}]

  describe "POST /api/v1/issuer/schemas" do
    test "creates a schema for the calling workspace", %{conn: conn} do
      %{api_key: key, workspace: ws} = setup_workspace()
      schema_id = "s-#{System.unique_integer([:positive])}"

      resp =
        conn
        |> authed(key)
        |> post("/api/v1/issuer/schemas", %{
          "schema_id" => schema_id,
          "credential_type" => "MembershipCredential",
          "name" => "Membership",
          "claims" => claims_param(),
          "validity_period" => "1y"
        })
        |> json_response(201)

      assert resp["schema_id"] == schema_id
      assert resp["credential_type"] == "MembershipCredential"
      assert resp["registration_status"] == "pending"

      # The schema landed on the key's workspace, not merely in the response.
      assert [persisted] = Issuer.list_schemas(ws.id)
      assert persisted.schema_id == schema_id
    end

    test "422 on a malformed validity period", %{conn: conn} do
      %{api_key: key} = setup_workspace()

      resp =
        conn
        |> authed(key)
        |> post("/api/v1/issuer/schemas", %{
          "schema_id" => "s-#{System.unique_integer([:positive])}",
          "credential_type" => "TestCredential",
          "name" => "Test",
          "claims" => claims_param(),
          "validity_period" => "1yr"
        })
        |> json_response(422)

      assert resp["error"] == "validation_error"
    end

    test "401 without API key", %{conn: conn} do
      conn = post(conn, "/api/v1/issuer/schemas", %{"name" => "Test"})
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end

  describe "GET /api/v1/issuer/schemas" do
    test "lists schemas for the calling workspace", %{conn: conn} do
      %{api_key: key, workspace: ws} = setup_workspace()
      schema = create_schema(ws.id)

      resp =
        conn
        |> authed(key)
        |> get("/api/v1/issuer/schemas")
        |> json_response(200)

      assert [%{"id" => id, "schema_id" => schema_id}] = resp["schemas"]
      assert id == schema.id
      assert schema_id == schema.schema_id
    end

    test "does not leak schemas from another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace()
      %{workspace: ws_b} = setup_workspace()
      schema_b = create_schema(ws_b.id)

      resp =
        conn
        |> authed(key_a)
        |> get("/api/v1/issuer/schemas")
        |> json_response(200)

      ids = Enum.map(resp["schemas"], & &1["id"])
      refute schema_b.id in ids
    end

    test "401 without API key", %{conn: conn} do
      conn = get(conn, "/api/v1/issuer/schemas")
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end

  describe "PUT /api/v1/issuer/schemas/:schema_id" do
    test "revises a schema into a new version", %{conn: conn} do
      %{api_key: key, workspace: ws} = setup_workspace()
      schema = create_schema(ws.id)

      resp =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/schemas/#{schema.schema_id}", %{
          "name" => "Renamed",
          "claims" => claims_param(),
          "validity_period" => "2y",
          "base_version" => schema.version
        })
        |> json_response(201)

      assert resp["name"] == "Renamed"
      assert resp["version"] == schema.version + 1
    end

    test "409 when the base version is stale", %{conn: conn} do
      %{api_key: key, workspace: ws} = setup_workspace()
      schema = create_schema(ws.id)

      conn
      |> authed(key)
      |> put("/api/v1/issuer/schemas/#{schema.schema_id}", %{
        "name" => "First",
        "claims" => claims_param(),
        "validity_period" => "1y",
        "base_version" => schema.version
      })
      |> json_response(201)

      # Second writer still holds the version it read before the first landed.
      resp =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/schemas/#{schema.schema_id}", %{
          "name" => "Second",
          "claims" => claims_param(),
          "validity_period" => "1y",
          "base_version" => schema.version
        })
        |> json_response(409)

      assert resp["error"] == "schema_revision_conflict"
    end

    test "404 for a schema in another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace()
      %{workspace: ws_b} = setup_workspace()
      schema_b = create_schema(ws_b.id)

      resp =
        conn
        |> authed(key_a)
        |> put("/api/v1/issuer/schemas/#{schema_b.schema_id}", %{
          "name" => "Hijacked",
          "claims" => claims_param(),
          "validity_period" => "1y",
          "base_version" => schema_b.version
        })
        |> json_response(404)

      assert resp["error"] == "schema_not_found"
    end

    test "401 without API key", %{conn: conn} do
      conn = put(conn, "/api/v1/issuer/schemas/whatever", %{"name" => "Test"})
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end

  describe "DELETE /api/v1/issuer/schemas/:id" do
    test "deletes a schema nothing has been issued from", %{conn: conn} do
      %{api_key: key, workspace: ws} = setup_workspace()
      schema = create_schema(ws.id)

      conn
      |> authed(key)
      |> delete("/api/v1/issuer/schemas/#{schema.id}")
      |> response(204)

      assert Issuer.list_schemas(ws.id) == []
    end

    test "404 for a schema in another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace()
      %{workspace: ws_b} = setup_workspace()
      schema_b = create_schema(ws_b.id)

      resp =
        conn
        |> authed(key_a)
        |> delete("/api/v1/issuer/schemas/#{schema_b.id}")
        |> json_response(404)

      assert resp["error"] == "schema_not_found"

      # The other workspace still has it.
      assert [kept] = Issuer.list_schemas(ws_b.id)
      assert kept.id == schema_b.id
    end

    test "401 without API key", %{conn: conn} do
      conn = delete(conn, "/api/v1/issuer/schemas/#{Ecto.UUID.generate()}")
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end
end
