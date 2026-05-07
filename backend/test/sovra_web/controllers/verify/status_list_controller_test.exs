defmodule SovraWeb.Verify.StatusListControllerTest do
  @moduledoc """
  Covers the public status-list endpoint at
  `GET /api/v1/status/:issuer_did/:purpose`. Input validation and lookup
  paths are exercised directly; the 200 / 304 happy paths use a process-local
  stub registry so the on-chain bitmap can be controlled per-test.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Credentials.SDJWT, as: SDJWTReader

  defmodule StubRegistry do
    def configure_bitmap(words), do: Process.put({__MODULE__, :bitmap}, words)
    def get_bitmap(_addr, _purpose), do: {:ok, Process.get({__MODULE__, :bitmap}, [0])}
  end

  setup do
    prev = Application.get_env(:sovra, :revocation_registry)
    Application.put_env(:sovra, :revocation_registry, StubRegistry)

    on_exit(fn ->
      case prev do
        nil -> Application.delete_env(:sovra, :revocation_registry)
        v -> Application.put_env(:sovra, :revocation_registry, v)
      end
    end)

    :ok
  end

  defp create_workspace, do: provision_workspace(fixture_workspace().workspace)

  test "400 on unknown purpose", %{conn: conn} do
    ws = create_workspace()

    resp =
      conn
      |> get("/api/v1/status/#{URI.encode(ws.did)}/garbage")
      |> json_response(400)

    assert resp == %{"error" => "invalid_purpose"}
  end

  test "404 when no workspace has that DID", %{conn: conn} do
    resp =
      conn
      |> get("/api/v1/status/did:sovra:0xdoesnotexist/revocation")
      |> json_response(404)

    assert resp == %{"error" => "issuer_not_found"}
  end

  test "404 when the URL slot is a workspace UUID instead of a DID", %{conn: conn} do
    ws = create_workspace()

    resp =
      conn
      |> get("/api/v1/status/#{ws.id}/revocation")
      |> json_response(404)

    assert resp == %{"error" => "issuer_not_found"}
  end

  describe "200 happy path" do
    test "returns a signed VC-JWT with ETag and verifiable signature", %{conn: conn} do
      ws = create_workspace()
      StubRegistry.configure_bitmap([0])

      conn = get(conn, "/api/v1/status/#{URI.encode(ws.did)}/revocation")

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") |> Enum.at(0) =~ "application/jwt"

      [etag] = get_resp_header(conn, "etag")
      assert String.starts_with?(etag, ~s("))
      assert String.ends_with?(etag, ~s("))

      assert get_resp_header(conn, "cache-control") == ["public, max-age=300"]

      jwt = conn.resp_body
      assert [_, _, _] = String.split(jwt, ".")

      assert :ok =
               SDJWTReader.verify_issuer_signature(jwt, %{
                 x: ws.signing_public_key_x,
                 y: ws.signing_public_key_y
               })

      [header, payload, _sig] = String.split(jwt, ".")
      digest = :crypto.hash(:sha256, header <> "." <> payload) |> Base.encode16(case: :lower)
      assert etag == ~s("#{digest}")
    end

    test "If-None-Match match returns 304 with empty body", %{conn: conn} do
      ws = create_workspace()
      StubRegistry.configure_bitmap([0])

      first = get(conn, "/api/v1/status/#{URI.encode(ws.did)}/revocation")
      [etag] = get_resp_header(first, "etag")

      second =
        conn
        |> put_req_header("if-none-match", etag)
        |> get("/api/v1/status/#{URI.encode(ws.did)}/revocation")

      assert second.status == 304
      assert second.resp_body == ""
    end

    test "different bitmap state ⇒ different ETag", %{conn: conn} do
      ws = create_workspace()

      StubRegistry.configure_bitmap([0])

      [etag1] =
        conn |> get("/api/v1/status/#{URI.encode(ws.did)}/revocation") |> get_resp_header("etag")

      StubRegistry.configure_bitmap([1])

      [etag2] =
        conn |> get("/api/v1/status/#{URI.encode(ws.did)}/revocation") |> get_resp_header("etag")

      refute etag1 == etag2
    end
  end
end
