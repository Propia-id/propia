defmodule SovraWeb.Verify.DocumentControllerTest do
  @moduledoc """
  Covers the two public document endpoints, `GET /api/v1/documents/:id` and
  `/:id/page`, and the visibility gate on both.

  The session for a private document arrives in `document_session`, the copy of
  the access cookie scoped to this path. A cookie is only sent to its own path,
  so the dashboard's `session` cookie never reaches here.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Auth.UserSession
  alias Sovra.Documents
  alias Sovra.Issuer

  @session_cookie "document_session"

  setup do
    workspace = provision_workspace(fixture_workspace().workspace)

    {:ok, schema} =
      Issuer.create_schema(workspace.id, %{
        schema_id: "letter-#{System.unique_integer([:positive])}",
        credential_type: "EmploymentLetter",
        name: "Employment letter",
        kind: "document",
        validity_period: "1y",
        claims: [%{"key" => "employee_name", "type" => "string", "required" => true}]
      })

    # A layout with one bound field, so the page actually renders the claim.
    # Without one it comes out with the provenance footer and nothing else.
    {:ok, _layout} =
      Documents.update_layout(workspace.id, schema.schema_id, %{
        "page" => %{"width" => 794, "height" => 1123},
        "elements" => [
          %{
            "id" => "n",
            "type" => "field",
            "x" => 48,
            "y" => 200,
            "size" => 14,
            "bind" => "employee_name"
          }
        ]
      })

    claims = %{"employee_name" => "Ada Lovelace"}

    {:ok, public} =
      Documents.issue(workspace.id, schema.schema_id, claims, visibility: "public")

    # No visibility given, so this one lands on the default.
    {:ok, private} = Documents.issue(workspace.id, schema.schema_id, claims)

    {:ok, token} = UserSession.create(Ecto.UUID.generate(), workspace.id, false)

    %{workspace: workspace, schema: schema, public: public, private: private, token: token}
  end

  describe "show/2" do
    test "serves a public document to an anonymous caller", %{conn: conn, public: document} do
      body = conn |> get(~p"/api/v1/documents/#{document.id}") |> json_response(200)

      assert body["id"] == document.id
      assert body["credential"] == document.credential
      assert body["anchor"]["status"] == "anchored"
      assert body["schema"]["name"] == "Employment letter"
    end

    test "answers any origin, so a verifier's app can read it", %{conn: conn, public: document} do
      conn = get(conn, ~p"/api/v1/documents/#{document.id}")

      assert get_resp_header(conn, "access-control-allow-origin") == ["*"]
    end

    test "refuses a private document with no session", %{conn: conn, private: document} do
      body = conn |> get(~p"/api/v1/documents/#{document.id}") |> json_response(401)

      assert body["error"] == "authentication_required"
    end

    test "serves a private document to a session", %{conn: conn, private: document, token: token} do
      body =
        conn
        |> put_req_cookie(@session_cookie, token)
        |> get(~p"/api/v1/documents/#{document.id}")
        |> json_response(200)

      assert body["id"] == document.id
    end

    test "refuses a private document with a bad token", %{conn: conn, private: document} do
      body =
        conn
        |> put_req_cookie(@session_cookie, "not-a-jwt")
        |> get(~p"/api/v1/documents/#{document.id}")
        |> json_response(401)

      assert body["error"] == "authentication_required"
    end

    test "accepts a session as a bearer header too", %{
      conn: conn,
      private: document,
      token: token
    } do
      body =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> get(~p"/api/v1/documents/#{document.id}")
        |> json_response(200)

      assert body["id"] == document.id
    end

    test "404 for an unknown id", %{conn: conn} do
      body = conn |> get(~p"/api/v1/documents/#{Ecto.UUID.generate()}") |> json_response(404)

      assert body["error"] == "document_not_found"
    end

    test "404 for a malformed id", %{conn: conn} do
      assert conn |> get(~p"/api/v1/documents/not-a-uuid") |> json_response(404)
    end
  end

  describe "page/2" do
    test "renders a public document", %{conn: conn, public: document} do
      conn = get(conn, ~p"/api/v1/documents/#{document.id}/page")

      assert html_response(conn, 200) =~ "Ada Lovelace"
      assert get_resp_header(conn, "content-security-policy") != []
    end

    test "refuses a private document with no session", %{conn: conn, private: document} do
      conn = get(conn, ~p"/api/v1/documents/#{document.id}/page")

      assert html_response(conn, 401) =~ "private"
    end

    test "renders a private document to a session", %{
      conn: conn,
      private: document,
      token: token
    } do
      conn =
        conn
        |> put_req_cookie(@session_cookie, token)
        |> get(~p"/api/v1/documents/#{document.id}/page")

      assert html_response(conn, 200) =~ "Ada Lovelace"
    end

    test "escapes a claim value that carries markup", %{
      conn: conn,
      workspace: workspace,
      schema: schema
    } do
      {:ok, document} =
        Documents.issue(
          workspace.id,
          schema.schema_id,
          %{"employee_name" => "<img src=x onerror=\"alert(1)\">"},
          visibility: "public"
        )

      html = conn |> get(~p"/api/v1/documents/#{document.id}/page") |> html_response(200)

      refute html =~ "<img src=x"
      assert html =~ "&lt;img src=x"
    end
  end
end
