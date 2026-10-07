defmodule SovraWeb.Issuer.DocumentValidUntilTest do
  @moduledoc """
  Covers the `valid_until` contract on `POST /dashboard/issuer/documents`.

  The same rule the credential offer endpoint enforces: omit the key to derive
  expiry from the schema's `validity_period`, or state an absolute instant.
  An explicit null, a past date, a malformed string or a non-string is a 422,
  never a silently substituted default.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Auth.UserSession
  alias Sovra.Issuer

  defp setup_workspace do
    %{workspace: ws, owner: user} = fixture_workspace(name: "Acme")
    %{workspace: provision_workspace(ws), user: user}
  end

  defp create_schema(workspace_id) do
    {:ok, schema} =
      Issuer.create_schema(workspace_id, %{
        schema_id: "letter-#{System.unique_integer([:positive])}",
        credential_type: "EmploymentLetter",
        name: "Employment letter",
        kind: "document",
        validity_period: "1y",
        claims: [%{"key" => "employee_name", "type" => "string", "required" => true}]
      })

    register_schema(schema)
  end

  defp post_document(conn, ws, user, extra) do
    {:ok, token} = UserSession.create(user.id, ws.id, user.is_admin)

    params =
      Map.merge(
        %{
          "schema_id" => create_schema(ws.id).schema_id,
          "claims" => %{"employee_name" => "Ada Lovelace"}
        },
        extra
      )

    conn
    |> put_req_header("authorization", "Bearer #{token}")
    |> post("/dashboard/issuer/documents", params)
  end

  defp payload(credential) do
    [_header, payload | _] = credential |> String.trim_trailing("~") |> String.split(".")
    payload |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  describe "valid_until" do
    test "201 and the signed exp is the requested instant", %{conn: conn} do
      %{workspace: ws, user: user} = setup_workspace()
      valid_until = DateTime.add(DateTime.utc_now(), 1000, :day) |> DateTime.truncate(:second)

      resp =
        conn
        |> post_document(ws, user, %{"valid_until" => DateTime.to_iso8601(valid_until)})
        |> json_response(201)

      assert payload(resp["credential"])["exp"] == DateTime.to_unix(valid_until)
    end

    test "422 for a date in the past", %{conn: conn} do
      %{workspace: ws, user: user} = setup_workspace()
      past = DateTime.add(DateTime.utc_now(), -1, :day) |> DateTime.to_iso8601()

      resp =
        conn
        |> post_document(ws, user, %{"valid_until" => past})
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
      assert resp["details"] =~ "future"
    end

    test "422 for an explicit null rather than falling back to the schema", %{conn: conn} do
      %{workspace: ws, user: user} = setup_workspace()

      resp =
        conn
        |> post_document(ws, user, %{"valid_until" => nil})
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
    end

    test "422 for an unparseable string", %{conn: conn} do
      %{workspace: ws, user: user} = setup_workspace()

      resp =
        conn
        |> post_document(ws, user, %{"valid_until" => "whenever"})
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
    end

    test "422 for a non-string", %{conn: conn} do
      %{workspace: ws, user: user} = setup_workspace()

      resp =
        conn
        |> post_document(ws, user, %{"valid_until" => %{}})
        |> json_response(422)

      assert resp["error"] == "invalid_valid_until"
    end

    test "omitting the key keeps the schema-derived expiry", %{conn: conn} do
      %{workspace: ws, user: user} = setup_workspace()

      resp =
        conn
        |> post_document(ws, user, %{})
        |> json_response(201)

      signed = payload(resp["credential"])
      assert signed["exp"] == signed["iat"] + 365 * 86_400
    end
  end
end
