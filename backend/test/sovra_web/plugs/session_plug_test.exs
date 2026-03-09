defmodule SovraWeb.Plugs.SessionPlugTest do
  use SovraWeb.ConnCase, async: true

  alias SovraWeb.Plugs.SessionPlug

  describe "call/2" do
    test "assigns current_holder for valid token", %{conn: conn} do
      {:ok, token} = Sovra.Auth.Session.create("0xplug_test")

      conn =
        conn
        |> put_req_header("authorization", "Bearer #{token}")
        |> SessionPlug.call([])

      assert conn.assigns.current_holder.sovra_address == "0xplug_test"
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
  end
end
