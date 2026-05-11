defmodule SovraWeb.Guardian.RecoveryControllerTest do
  use SovraWeb.ConnCase, async: true

  import Sovra.GuardianHelpers

  describe "POST /wallet/recovery/initiate" do
    test "returns 401 without session", %{conn: conn} do
      conn = post(conn, "/wallet/recovery/initiate", %{})

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end

    test "returns 400 for missing fields", %{conn: conn} do
      holder = create_test_holder(test_address("recovery_missing"))

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/wallet/recovery/initiate", %{})

      assert %{"error" => "missing_required_fields"} = json_response(conn, 400)
    end

    test "returns 400 for invalid key hex", %{conn: conn} do
      holder = create_test_holder(test_address("recovery_bad_hex"))

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/wallet/recovery/initiate", %{
          "newKeyX" => "not-hex",
          "newKeyY" => "not-hex",
          "keyToReplace" => 0
        })

      assert %{"error" => "invalid_key_parameters"} = json_response(conn, 400)
    end
  end

  describe "POST /wallet/recovery/finalize" do
    test "returns 401 without session", %{conn: conn} do
      conn = post(conn, "/wallet/recovery/finalize")

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end
  end
end
