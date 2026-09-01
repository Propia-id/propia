defmodule SovraWeb.Verify.RequestControllerTest do
  use SovraWeb.ConnCase, async: false

  import Ecto.Query

  alias Sovra.Verification
  alias Sovra.Verification.Session

  defp create_workspace, do: provision_workspace(fixture_workspace(name: "Verifier").workspace)

  defp decode_jws(jwt) do
    [header, payload, _sig] = String.split(jwt, ".")

    {header |> Base.url_decode64!(padding: false) |> Jason.decode!(),
     payload |> Base.url_decode64!(padding: false) |> Jason.decode!()}
  end

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

  describe "GET /wallet/verifier/request/:session_id" do
    test "200 returns the signed OID4VP authorization request object", %{conn: conn} do
      ws = create_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      conn = get(conn, "/wallet/verifier/request/#{session.id}")

      assert response(conn, 200) == session.request_object

      assert ["application/oauth-authz-req+jwt"] =
               get_resp_header(conn, "content-type")
               |> Enum.map(&(&1 |> String.split(";") |> hd()))

      {header, payload} = decode_jws(session.request_object)

      assert header["alg"] == "ES256"
      assert header["typ"] == "oauth-authz-req+jwt"
      assert header["kid"] == "#{ws.did}#key-assert"

      assert payload["client_id"] == "decentralized_identifier:#{ws.did}"
      assert payload["response_type"] == "vp_token"
      assert payload["response_mode"] == "direct_post"
      assert payload["nonce"] == session.nonce
      assert payload["state"] == session.state
      assert payload["dcql_query"] == dcql_query()
      assert payload["exp"] == DateTime.to_unix(session.expires_at)
      assert payload["client_metadata"] == %{"client_name" => ws.name}

      assert String.contains?(
               payload["response_uri"],
               "/wallet/verifier/direct_post/#{session.id}"
             )
    end

    # Every other test here uses a bare `build_conn()`, which sends no Accept.
    test "200 when the wallet asks for application/oauth-authz-req+jwt", %{conn: conn} do
      ws = create_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      conn =
        conn
        |> put_req_header("accept", "application/oauth-authz-req+jwt")
        |> get("/wallet/verifier/request/#{session.id}")

      assert response(conn, 200) == session.request_object
    end

    test "200 the request object verifies under the workspace's on-chain key", %{conn: conn} do
      ws = create_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      jwt = response(get(conn, "/wallet/verifier/request/#{session.id}"), 200)
      [header, payload, sig] = String.split(jwt, ".")
      <<r::binary-size(32), s::binary-size(32)>> = Base.url_decode64!(sig, padding: false)

      assert Sovra.Crypto.P256.verify(
               :crypto.hash(:sha256, "#{header}.#{payload}"),
               %{r: r, s: s},
               {ws.signing_public_key_x, ws.signing_public_key_y}
             )
    end

    test "404 for unknown session", %{conn: conn} do
      resp =
        conn
        |> get("/wallet/verifier/request/#{Ecto.UUID.generate()}")
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
        |> get("/wallet/verifier/request/#{session.id}")
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end
  end
end
