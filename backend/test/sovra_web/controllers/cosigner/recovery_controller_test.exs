defmodule SovraWeb.Cosigner.RecoveryControllerTest do
  use SovraWeb.ConnCase, async: true

  import Sovra.CosignerHelpers

  describe "POST /api/v1/recovery/initiate" do
    test "returns recovery signature", %{conn: conn} do
      holder = create_test_holder("0xrecovery_ctrl_test")
      {:ok, %{public_key_x: x, public_key_y: y}} = Sovra.Crypto.P256.generate_key_pair()

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/recovery/initiate", %{
          "newPasskeyPublicKey" => %{
            "x" => Base.encode64(x, padding: false),
            "y" => Base.encode64(y, padding: false)
          }
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
end
