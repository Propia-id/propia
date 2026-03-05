defmodule SovraWeb.Cosigner.RotateControllerTest do
  use SovraWeb.ConnCase, async: true

  import Sovra.CosignerHelpers

  describe "POST /api/v1/cosigner/rotate-server-key" do
    test "returns new public key and rotation signature", %{conn: conn} do
      holder = create_test_holder("0xrotate_ctrl_test")

      conn =
        conn
        |> auth_conn(holder.sovra_address)
        |> post("/api/v1/cosigner/rotate-server-key")

      assert %{
               "newServerPublicKey" => %{"x" => _, "y" => _},
               "rotationSignature" => %{"r" => "0x" <> _, "s" => "0x" <> _}
             } = json_response(conn, 200)
    end

    test "returns 401 without session", %{conn: conn} do
      conn = post(conn, "/api/v1/cosigner/rotate-server-key")

      assert %{"error" => "missing_authorization"} = json_response(conn, 401)
    end
  end
end
