defmodule SovraWeb.Verifier.VerificationControllerTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces.ApiKeys
  alias Sovra.Workspaces.Workspace

  defp create_user, do: fixture_user()

  defp create_workspace do
    %{workspace: ws, org: org} = fixture_workspace(name: "Verifier")
    %{workspace: provision_workspace(ws), organization: org}
  end

  defp dcql_query do
    %{
      "credentials" => [
        %{
          "id" => "diploma",
          "format" => "jwt_vc_json",
          "claims" => [%{"path" => ["studentName"]}]
        }
      ]
    }
  end

  describe "POST /api/v1/verifier/verifications" do
    test "201 with session id and authorization request URI", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(201)

      assert resp["session_id"]
      assert String.starts_with?(resp["authorization_request_uri"], "openid4vp://")
      assert resp["status"] == "pending"
      assert resp["expires_at"]
    end

    test "401 without API key", %{conn: conn} do
      conn = post(conn, "/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "401 with revoked API key", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key, record: rec}} = ApiKeys.create_api_key(ws.id, "Tmp")
      {:ok, _} = ApiKeys.revoke_api_key(rec)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "400 when dcql_query is missing", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{})
        |> json_response(400)

      assert resp == %{"error" => "missing_dcql_query"}
    end

    test "400 when dcql_query is malformed (no credentials list)", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => %{"foo" => "bar"}})
        |> json_response(400)

      assert resp == %{"error" => "invalid_dcql_query"}
    end

    test "403 when workspace is suspended", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      {:ok, _} =
        ws |> Workspace.status_changeset("suspended") |> Sovra.Repo.update()

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(403)

      assert resp == %{"error" => "workspace_inactive"}
    end

    test "403 when organization is suspended", %{conn: conn} do
      %{workspace: ws, organization: org} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      {:ok, _} =
        org |> Organization.status_changeset("suspended") |> Sovra.Repo.update()

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(403)

      assert resp == %{"error" => "organization_inactive"}
    end

    test "201 also includes a pass-by-reference URI", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(201)

      assert String.starts_with?(resp["authorization_request_uri_ref"], "openid4vp://")
      assert String.contains?(resp["authorization_request_uri_ref"], "request_uri=")
    end
  end

  describe "GET /api/v1/verifier/verifications/:id" do
    test "200 with the session for the owning workspace", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      session_id =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(201)
        |> Map.fetch!("session_id")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> get("/api/v1/verifier/verifications/#{session_id}")
        |> json_response(200)

      assert resp["session_id"] == session_id
      assert resp["status"] == "pending"
      assert resp["expires_at"]
      assert resp["dcql_query"]
      assert resp["holder_did"] == nil
      assert resp["presentation_data"] == nil
      assert resp["completed_at"] == nil
    end

    test "404 cross-tenant lookup", %{conn: conn} do
      %{workspace: ws_a} = create_workspace()
      %{workspace: ws_b} = create_workspace()
      {:ok, %{api_key: key_a}} = ApiKeys.create_api_key(ws_a.id, "A")
      {:ok, %{api_key: key_b}} = ApiKeys.create_api_key(ws_b.id, "B")

      session_id =
        conn
        |> put_req_header("authorization", "Bearer #{key_a}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(201)
        |> Map.fetch!("session_id")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key_b}")
        |> get("/api/v1/verifier/verifications/#{session_id}")
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end

    test "404 unknown id", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> get("/api/v1/verifier/verifications/#{Ecto.UUID.generate()}")
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end

    test "401 without auth", %{conn: conn} do
      conn =
        conn
        |> get("/api/v1/verifier/verifications/#{Ecto.UUID.generate()}")

      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end

    test "403 when workspace is suspended", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      session_id =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(201)
        |> Map.fetch!("session_id")

      {:ok, _} =
        ws |> Workspace.status_changeset("suspended") |> Sovra.Repo.update()

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> get("/api/v1/verifier/verifications/#{session_id}")
        |> json_response(403)

      assert resp == %{"error" => "workspace_inactive"}
    end
  end

  describe "GET /api/v1/verifier/verifications" do
    test "200 with the workspace's sessions", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      for _ <- 1..3 do
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(201)
      end

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> get("/api/v1/verifier/verifications")
        |> json_response(200)

      assert length(resp["sessions"]) == 3
      assert resp["limit"] == 50
      assert resp["offset"] == 0
    end

    test "200 with empty list for a fresh workspace", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> get("/api/v1/verifier/verifications")
        |> json_response(200)

      assert resp["sessions"] == []
    end

    test "honors status filter and pagination", %{conn: conn} do
      %{workspace: ws} = create_workspace()
      {:ok, %{api_key: key}} = ApiKeys.create_api_key(ws.id, "Prod")

      for _ <- 1..3 do
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
        |> json_response(201)
      end

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> get("/api/v1/verifier/verifications?status=pending&limit=2")
        |> json_response(200)

      assert length(resp["sessions"]) == 2
      assert resp["limit"] == 2

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key}")
        |> get("/api/v1/verifier/verifications?status=completed")
        |> json_response(200)

      assert resp["sessions"] == []
    end

    test "doesn't leak sessions from other workspaces", %{conn: conn} do
      %{workspace: ws_a} = create_workspace()
      %{workspace: ws_b} = create_workspace()
      {:ok, %{api_key: key_a}} = ApiKeys.create_api_key(ws_a.id, "A")
      {:ok, %{api_key: key_b}} = ApiKeys.create_api_key(ws_b.id, "B")

      conn
      |> put_req_header("authorization", "Bearer #{key_a}")
      |> post("/api/v1/verifier/verifications", %{"dcql_query" => dcql_query()})
      |> json_response(201)

      resp =
        conn
        |> put_req_header("authorization", "Bearer #{key_b}")
        |> get("/api/v1/verifier/verifications")
        |> json_response(200)

      assert resp["sessions"] == []
    end

    test "401 without auth", %{conn: conn} do
      conn = get(conn, "/api/v1/verifier/verifications")
      assert json_response(conn, 401) == %{"error" => "invalid_api_key"}
    end
  end
end
