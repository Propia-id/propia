defmodule SovraWeb.Guardian.RecoveryControllerTest do
  use SovraWeb.ConnCase, async: true

  import Sovra.GuardianHelpers

  describe "POST /api/v1/recovery/initiate" do
    test "returns recovery signature", %{conn: conn} do
      holder = create_test_holder("0xrecovery_ctrl_test")
      message_hash = random_hash()

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/initiate", %{
          "messageHash" => hex_hash(message_hash)
        })

      assert %{"signature" => %{"r" => "0x" <> _, "s" => "0x" <> _}} = json_response(conn, 200)
    end

    test "returns 401 without session", %{conn: conn} do
      conn = post(conn, "/api/v1/recovery/initiate", %{})

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end

    test "returns 400 for missing fields", %{conn: conn} do
      holder = create_test_holder("0xrecovery_missing")

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/initiate", %{})

      assert %{"error" => "missing_required_fields"} = json_response(conn, 400)
    end
  end

  describe "POST /api/v1/recovery/finalize" do
    test "returns signature after initiating recovery", %{conn: conn} do
      holder = create_test_holder("0xfinalize_ctrl_test")

      # First initiate recovery to set status to recovery_pending
      {:ok, _} = Sovra.Cosigner.initiate_recovery(holder.sovra_address, random_hash())

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/finalize", %{
          "messageHash" => hex_hash(random_hash())
        })

      assert %{"signature" => %{"r" => "0x" <> _, "s" => "0x" <> _}} = json_response(conn, 200)
    end

    test "returns 422 for holder not in recovery", %{conn: conn} do
      holder = create_test_holder("0xfinalize_not_pending")

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/finalize", %{
          "messageHash" => hex_hash(random_hash())
        })

      assert %{"error" => "not_in_recovery"} = json_response(conn, 422)
    end

    test "returns 400 for missing fields", %{conn: conn} do
      holder = create_test_holder("0xfinalize_missing")

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/finalize", %{})

      assert %{"error" => "missing_required_fields"} = json_response(conn, 400)
    end

    test "returns 401 without session", %{conn: conn} do
      conn = post(conn, "/api/v1/recovery/finalize")

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end
  end
end
