defmodule SovraWeb.Verify.RequestControllerTest do
  use SovraWeb.ConnCase, async: false

  import Ecto.Query

  alias Sovra.Verification
  alias Sovra.Verification.Session

  defp create_workspace, do: fixture_workspace(name: "Verifier").workspace

  defp dcql_query do
    %{
      "credentials" => [
        %{
          "id" => "diploma",
          "format" => "vc+sd-jwt",
          "claims" => [%{"path" => ["studentName"]}]
        }
      ]
    }
  end

  describe "GET /api/v1/verify/request/:session_id" do
    test "200 returns the OID4VP authorization request object", %{conn: conn} do
      ws = create_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      resp =
        conn
        |> get("/api/v1/verify/request/#{session.id}")
        |> json_response(200)

      assert resp["client_id"] == "verifier:#{ws.id}"
      assert resp["response_type"] == "vp_token"
      assert resp["response_mode"] == "direct_post"
      assert resp["nonce"] == session.nonce
      assert resp["state"] == session.state
      assert resp["dcql_query"] == dcql_query()
      assert String.contains?(resp["response_uri"], "/api/v1/verify/direct_post/#{session.id}")
    end

    test "404 for unknown session", %{conn: conn} do
      resp =
        conn
        |> get("/api/v1/verify/request/#{Ecto.UUID.generate()}")
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end

    test "404 once the session is expired", %{conn: conn} do
      ws = create_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      past = DateTime.utc_now() |> DateTime.add(-3600, :second) |> DateTime.truncate(:second)

      Sovra.Repo.update_all(
        from(s in Session, where: s.id == ^session.id),
        set: [expires_at: past]
      )

      resp =
        conn
        |> get("/api/v1/verify/request/#{session.id}")
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end
  end
end
