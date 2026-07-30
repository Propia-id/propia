defmodule SovraWeb.Plugs.CorsTest do
  use SovraWeb.ConnCase, async: false

  alias SovraWeb.AllowedOrigins
  alias SovraWeb.Plugs.Cors

  @issuer "https://test-issuer-sovra.example.com"
  @other "https://evil.example.com"

  setup do
    previous = Application.get_env(:sovra, :issuer_frontend_url)
    extras = Application.get_env(:sovra, :additional_allowed_origins)
    Application.put_env(:sovra, :issuer_frontend_url, @issuer)

    on_exit(fn ->
      Application.put_env(:sovra, :issuer_frontend_url, previous)

      if extras do
        Application.put_env(:sovra, :additional_allowed_origins, extras)
      else
        Application.delete_env(:sovra, :additional_allowed_origins)
      end
    end)

    :ok
  end

  defp preflight(origin) do
    Phoenix.ConnTest.build_conn(:options, "/dashboard/auth/register")
    |> Plug.Conn.put_req_header("origin", origin)
    |> Plug.Conn.put_req_header("access-control-request-method", "POST")
    |> Cors.call([])
  end

  defp allow_origin(conn), do: Plug.Conn.get_resp_header(conn, "access-control-allow-origin")

  describe "preflight" do
    test "allows the configured issuer origin" do
      conn = preflight(@issuer)

      assert conn.status == 204
      assert allow_origin(conn) == [@issuer]
      assert Plug.Conn.get_resp_header(conn, "access-control-allow-credentials") == ["true"]
      assert Plug.Conn.get_resp_header(conn, "access-control-max-age") == ["86400"]
    end

    test "sends no allow-origin for an unknown origin" do
      assert allow_origin(preflight(@other)) == []
    end

    test "allows an extra configured origin" do
      Application.put_env(:sovra, :additional_allowed_origins, [@other])

      assert allow_origin(preflight(@other)) == [@other]
    end
  end

  describe "runtime resolution" do
    # The bug this guards: CORSPlug plugged directly reads its config in
    # init/1, which in a release runs at compile time — so the origin set by
    # runtime.exs at boot was ignored and every preflight came back without an
    # allow-origin header.
    test "follows a change made after the pipeline was built" do
      assert allow_origin(preflight(@issuer)) == [@issuer]

      rebranded = "https://issuer.sovra.example"
      Application.put_env(:sovra, :issuer_frontend_url, rebranded)

      assert allow_origin(preflight(rebranded)) == [rebranded]
      assert allow_origin(preflight(@issuer)) == []
    end

    test "allows nothing when no origin is configured" do
      Application.put_env(:sovra, :issuer_frontend_url, "")

      assert AllowedOrigins.list() == []
      assert allow_origin(preflight(@issuer)) == []
    end
  end

  describe "non-preflight requests" do
    test "carry the allow-origin header for an allowed origin" do
      conn =
        Phoenix.ConnTest.build_conn(:post, "/dashboard/auth/register")
        |> Plug.Conn.put_req_header("origin", @issuer)
        |> Cors.call([])

      refute conn.halted
      assert allow_origin(conn) == [@issuer]
    end
  end

  describe "AllowedOrigins" do
    test "is the list the origin check plug uses too" do
      Application.put_env(:sovra, :additional_allowed_origins, [@other])

      assert AllowedOrigins.list() == [@issuer, @other]
    end

    test "drops blank and nil entries" do
      Application.put_env(:sovra, :additional_allowed_origins, [nil, "", @other])

      assert AllowedOrigins.list() == [@issuer, @other]
    end
  end
end
