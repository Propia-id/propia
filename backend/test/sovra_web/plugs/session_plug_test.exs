defmodule SovraWeb.Plugs.SessionPlugTest do
  use SovraWeb.ConnCase, async: true

  alias SovraWeb.Plugs.SessionPlug

  @test_address "0x" <> String.duplicate("ab", 20)

  describe "call/2" do
    test "assigns current_holder for valid token", %{conn: conn} do
      {:ok, token} = Sovra.Auth.Session.create(@test_address)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> SessionPlug.call([])

      assert conn.assigns.current_holder.sovra_address == @test_address
      refute conn.halted
    end

    test "returns 401 for missing authorization header", %{conn: conn} do
      conn = SessionPlug.call(conn, [])

      assert conn.halted
      assert conn.status == 401
    end

    test "returns 401 for invalid token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer invalid-token")
        |> SessionPlug.call([])

      assert conn.halted
      assert conn.status == 401
    end

    test "returns 403 when max_age exceeded", %{conn: conn} do
      # Create a token with iat in the past (10 minutes ago)
      now = System.system_time(:second)
      old_iat = now - 600

      jwk = Sovra.Auth.KeyDerivation.derive_key(:guardian_session) |> JOSE.JWK.from_oct()

      claims = %{
        "sub" => @test_address,
        "scope" => "guardian",
        "iss" => "sovra-guardian",
        "aud" => "sovra-guardian",
        "jti" => "test-jti",
        "iat" => old_iat,
        "exp" => now + 300
      }

      {_, token} = JOSE.JWT.sign(jwk, %{"alg" => "HS256"}, claims) |> JOSE.JWS.compact()

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> SessionPlug.call(max_age: 300)

      assert conn.halted
      assert conn.status == 403

      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "session_not_fresh"
    end

    test "passes fresh auth check when token is recent", %{conn: conn} do
      {:ok, token} = Sovra.Auth.Session.create(@test_address)

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> SessionPlug.call(max_age: 300)

      assert conn.assigns.current_holder.sovra_address == @test_address
      refute conn.halted
    end
  end
end
