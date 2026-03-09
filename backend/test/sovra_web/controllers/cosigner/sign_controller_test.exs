defmodule SovraWeb.Cosigner.SignControllerTest do
  use SovraWeb.ConnCase, async: true

  import Sovra.CosignerHelpers

  describe "POST /api/v1/cosigner/cosign" do
    test "returns signature for valid request", %{conn: conn} do
      holder = create_test_holder("0xsign_test")
      hash = random_hash()

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/cosigner/cosign", %{"hash" => hex_hash(hash)})

      assert %{"signature" => %{"r" => "0x" <> _, "s" => "0x" <> _}} = json_response(conn, 200)
    end

    test "returns 401 without session token", %{conn: conn} do
      conn = post(conn, "/api/v1/cosigner/cosign", %{"hash" => hex_hash(random_hash())})

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end

    test "returns 400 for invalid hash", %{conn: conn} do
      holder = create_test_holder("0xbad_hash_test")

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/cosigner/cosign", %{"hash" => "0xdeadbeef"})

      assert %{"error" => _} = json_response(conn, 400)
    end

    test "returns 400 for missing hash", %{conn: conn} do
      holder = create_test_holder("0xno_hash_test")

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/cosigner/cosign", %{})

      assert %{"error" => "missing_or_invalid_hash"} = json_response(conn, 400)
    end
  end
end
