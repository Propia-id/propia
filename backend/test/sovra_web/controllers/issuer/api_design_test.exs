defmodule SovraWeb.Issuer.ApiDesignTest do
  @moduledoc """
  Covers the API-key-authenticated credential design surface:

      GET    /api/v1/issuer/schemas/:schema_id/design
      PUT    /api/v1/issuer/schemas/:schema_id/design
      DELETE /api/v1/issuer/schemas/:schema_id/design

  The design is the write side of the DIF Credential Manifest
  `output_descriptor` wallets read from /wallet/issuer/credential-manifests,
  so the round-trip test here asserts the manifest reflects what was written
  rather than only that the write returned 200.

  The same controller actions back the dashboard mount under
  `/dashboard/issuer/schemas/:schema_id/design`. Both pipelines resolve the
  tenant through `conn.assigns.current_workspace_id`.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Issuer
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKeys

  defp setup_workspace_with_schema do
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

    {:ok, schema} =
      Issuer.create_schema(ws.id, %{
        schema_id: "s-#{System.unique_integer([:positive])}",
        credential_type: "MembershipCredential",
        name: "Membership",
        claims: [
          %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    %{workspace: ws, api_key: key, schema: register_schema(schema)}
  end

  defp authed(conn, key), do: put_req_header(conn, "authorization", "Bearer #{key}")

  defp design_payload(overrides \\ %{}) do
    Map.merge(
      %{
        "name" => "Membership card",
        "description" => "The card a member carries",
        "display" => %{
          "title" => %{"text" => "Membership"},
          "subtitle" => %{"path" => ["$.name"], "fallback" => "Member"},
          "properties" => [%{"label" => "Name", "path" => ["$.name"]}]
        },
        "styles" => %{
          "background" => %{"color" => "#112233"},
          "text" => %{"color" => "#ffffff"}
        }
      },
      overrides
    )
  end

  describe "PUT /api/v1/issuer/schemas/:schema_id/design" do
    test "creates a design for the schema", %{conn: conn} do
      %{api_key: key, schema: schema, workspace: ws} = setup_workspace_with_schema()

      resp =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/schemas/#{schema.schema_id}/design", design_payload())
        |> json_response(200)

      assert resp["name"] == "Membership card"
      assert resp["credential_schema_id"] == schema.id
      assert resp["display"]["title"]["text"] == "Membership"
      assert resp["styles"]["background"]["color"] == "#112233"

      assert {:ok, persisted} = Issuer.get_design(ws.id, schema.schema_id)
      assert persisted.name == "Membership card"
    end

    test "a second write updates the design in place", %{conn: conn} do
      %{api_key: key, schema: schema, workspace: ws} = setup_workspace_with_schema()

      first =
        conn
        |> authed(key)
        |> put("/api/v1/issuer/schemas/#{schema.schema_id}/design", design_payload())
        |> json_response(200)

      second =
        conn
        |> authed(key)
        |> put(
          "/api/v1/issuer/schemas/#{schema.schema_id}/design",
          design_payload(%{"name" => "Renamed card"})
        )
        |> json_response(200)

      assert second["id"] == first["id"]
      assert second["name"] == "Renamed card"

      # Upsert, not insert: the workspace still has exactly one design.
      assert [only] = Issuer.list_designs(ws.id)
      assert only.name == "Renamed card"
    end

    test "the design reaches the manifest wallets read", %{conn: conn} do
      %{api_key: key, schema: schema} = setup_workspace_with_schema()

      conn
      |> authed(key)
      |> put("/api/v1/issuer/schemas/#{schema.schema_id}/design", design_payload())
      |> json_response(200)

      descriptor =
        conn
        |> get("/wallet/issuer/credential-manifests/#{schema.schema_id}")
        |> json_response(200)

      assert descriptor["display"]["title"]["text"] == "Membership"
    end

    test "422 when a display mapping has neither text nor path", %{conn: conn} do
      %{api_key: key, schema: schema} = setup_workspace_with_schema()

      resp =
        conn
        |> authed(key)
        |> put(
          "/api/v1/issuer/schemas/#{schema.schema_id}/design",
          design_payload(%{"display" => %{"title" => %{"fallback" => "nothing to render"}}})
        )
        |> json_response(422)

      assert resp["error"] == "validation_error"
    end

    test "404 for a schema in another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace_with_schema()
      %{schema: schema_b, workspace: ws_b} = setup_workspace_with_schema()

      resp =
        conn
        |> authed(key_a)
        |> put("/api/v1/issuer/schemas/#{schema_b.schema_id}/design", design_payload())
        |> json_response(404)

      assert resp["error"] == "schema_not_found"
      assert Issuer.list_designs(ws_b.id) == []
    end

    test "401 without API key", %{conn: conn} do
      conn = put(conn, "/api/v1/issuer/schemas/whatever/design", design_payload())
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end

  describe "GET /api/v1/issuer/schemas/:schema_id/design" do
    test "returns the design", %{conn: conn} do
      %{api_key: key, schema: schema} = setup_workspace_with_schema()

      conn
      |> authed(key)
      |> put("/api/v1/issuer/schemas/#{schema.schema_id}/design", design_payload())
      |> json_response(200)

      resp =
        conn
        |> authed(key)
        |> get("/api/v1/issuer/schemas/#{schema.schema_id}/design")
        |> json_response(200)

      assert resp["name"] == "Membership card"
      # The serializer emits every embed key, nulls included, so match on the
      # two that were written rather than on the whole map.
      assert [%{"label" => "Name", "path" => ["$.name"]}] = resp["display"]["properties"]
    end

    test "404 when the schema has no design yet", %{conn: conn} do
      %{api_key: key, schema: schema} = setup_workspace_with_schema()

      resp =
        conn
        |> authed(key)
        |> get("/api/v1/issuer/schemas/#{schema.schema_id}/design")
        |> json_response(404)

      assert resp["error"] == "design_not_found"
    end

    test "404 for a schema in another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace_with_schema()
      %{api_key: key_b, schema: schema_b} = setup_workspace_with_schema()

      conn
      |> authed(key_b)
      |> put("/api/v1/issuer/schemas/#{schema_b.schema_id}/design", design_payload())
      |> json_response(200)

      resp =
        conn
        |> authed(key_a)
        |> get("/api/v1/issuer/schemas/#{schema_b.schema_id}/design")
        |> json_response(404)

      assert resp["error"] == "schema_not_found"
    end

    test "401 without API key", %{conn: conn} do
      conn = get(conn, "/api/v1/issuer/schemas/whatever/design")
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end

  describe "DELETE /api/v1/issuer/schemas/:schema_id/design" do
    test "removes the design and leaves the schema", %{conn: conn} do
      %{api_key: key, schema: schema, workspace: ws} = setup_workspace_with_schema()

      conn
      |> authed(key)
      |> put("/api/v1/issuer/schemas/#{schema.schema_id}/design", design_payload())
      |> json_response(200)

      conn
      |> authed(key)
      |> delete("/api/v1/issuer/schemas/#{schema.schema_id}/design")
      |> response(204)

      assert Issuer.list_designs(ws.id) == []
      assert [kept] = Issuer.list_schemas(ws.id)
      assert kept.id == schema.id
    end

    test "404 when there is no design", %{conn: conn} do
      %{api_key: key, schema: schema} = setup_workspace_with_schema()

      resp =
        conn
        |> authed(key)
        |> delete("/api/v1/issuer/schemas/#{schema.schema_id}/design")
        |> json_response(404)

      assert resp["error"] == "design_not_found"
    end

    test "404 for a schema in another workspace", %{conn: conn} do
      %{api_key: key_a} = setup_workspace_with_schema()
      %{api_key: key_b, schema: schema_b, workspace: ws_b} = setup_workspace_with_schema()

      conn
      |> authed(key_b)
      |> put("/api/v1/issuer/schemas/#{schema_b.schema_id}/design", design_payload())
      |> json_response(200)

      resp =
        conn
        |> authed(key_a)
        |> delete("/api/v1/issuer/schemas/#{schema_b.schema_id}/design")
        |> json_response(404)

      assert resp["error"] == "schema_not_found"
      assert [_kept] = Issuer.list_designs(ws_b.id)
    end

    test "401 without API key", %{conn: conn} do
      conn = delete(conn, "/api/v1/issuer/schemas/whatever/design")
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end
end
