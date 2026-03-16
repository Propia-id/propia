defmodule SovraWeb.Guardian.RecoveryControllerTest do
  use SovraWeb.ConnCase, async: true

  import Sovra.GuardianHelpers

  describe "POST /api/v1/recovery/initiate" do
    test "returns 401 without session", %{conn: conn} do
      conn = post(conn, "/api/v1/recovery/initiate", %{})

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end

    test "returns 400 for missing fields", %{conn: conn} do
      holder = create_test_holder(test_address("recovery_missing"))

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/initiate", %{})

      assert %{"error" => "missing_required_fields"} = json_response(conn, 400)
    end

    test "returns 400 for invalid key hex", %{conn: conn} do
      holder = create_test_holder(test_address("recovery_bad_hex"))

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/initiate", %{
          "newKeyX" => "not-hex",
          "newKeyY" => "not-hex",
          "keyToReplace" => 0
        })

      assert %{"error" => "invalid_key_parameters"} = json_response(conn, 400)
    end
  end

  describe "POST /api/v1/recovery/finalize" do
    test "returns 422 for holder not in recovery", %{conn: conn} do
      holder = create_test_holder(test_address("finalize_not_pending"))

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/finalize", %{})

      assert %{"error" => "not_in_recovery"} = json_response(conn, 422)
    end

    test "returns 401 without session", %{conn: conn} do
      conn = post(conn, "/api/v1/recovery/finalize")

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end
  end
end
