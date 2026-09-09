defmodule Sovra.Signer.RouterTest do
  # async: false — the probe tests start the named Health singleton.
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias Sovra.BuildInfo
  alias Sovra.Crypto.P256
  alias Sovra.Signer.{Health, Router}

  @opts Router.init([])
  # Matches config :sovra, :signer_service, token: ... in config/test.exs
  @token "test-signer-token"

  defp call(method, path, body, opts \\ []) do
    token = Keyword.get(opts, :token, @token)

    conn(method, path, Jason.encode!(body))
    |> put_req_header("content-type", "application/json")
    |> then(fn c ->
      if token, do: put_req_header(c, "authorization", "Bearer " <> token), else: c
    end)
    |> Router.call(@opts)
  end

  # Liveness and readiness are split the same way the API splits them: /health
  # must never fail for a dependency, /ready must.
  describe "GET /health" do
    test "answers without a bearer token" do
      conn = call(:get, "/health", %{}, token: nil)

      refute conn.status == 401
      assert %{"status" => "ok"} = Jason.decode!(conn.resp_body)
    end

    # The whole point of the split: KMS being down must not make this fail.
    test "200 regardless of the KMS verdict, and carries no dependency detail" do
      put_relayer_key("no-such-relayer-key")
      start_health()
      assert Health.check_now() == :error

      conn = call(:get, "/health", %{}, token: nil)

      assert conn.status == 200
      assert Jason.decode!(conn.resp_body) == Map.put(build_fields(), "status", "ok")
    end

    # `signer_deploy` asserts on these, so the values matter, not just the keys.
    test "carries the build identity" do
      body = Jason.decode!(call(:get, "/health", %{}, token: nil).resp_body)

      assert body["revision"] == BuildInfo.revision()
      assert body["ref"] == BuildInfo.ref()
      assert body["version"] == BuildInfo.version()
      assert body["built_at"] == BuildInfo.built_at()
    end

    # Only GET is exempt: anything else on the path is an ordinary request.
    test "a non-GET /health still requires the token" do
      assert call(:post, "/health", %{}, token: nil).status == 401
      assert call(:post, "/health", %{}).status == 404
    end
  end

  describe "GET /ready" do
    test "answers without a bearer token" do
      refute call(:get, "/ready", %{}, token: nil).status == 401
    end

    test "200 ok once the KMS probe has succeeded" do
      start_health()
      assert Health.check_now() == :ok

      conn = call(:get, "/ready", %{}, token: nil)
      body = Jason.decode!(conn.resp_body)

      assert conn.status == 200
      assert body["status"] == "ok"
      assert body["checks"] == %{"kms" => %{"status" => "ok"}}
      assert {:ok, _, _} = DateTime.from_iso8601(body["checked_at"])
    end

    test "503 error when the KMS probe fails" do
      put_relayer_key("no-such-relayer-key")
      start_health()
      assert Health.check_now() == :error

      conn = call(:get, "/ready", %{}, token: nil)

      assert conn.status == 503
      assert Jason.decode!(conn.resp_body)["status"] == "error"
    end

    # The monitor is not running, so there is no verdict to serve. Not ready.
    test "503 unavailable when the monitor is not running" do
      conn = call(:get, "/ready", %{}, token: nil)

      assert conn.status == 503

      assert Jason.decode!(conn.resp_body) == %{
               "status" => "unavailable",
               "checked_at" => nil,
               "checks" => %{}
             }
    end

    # No build identity here: that is /health's job, and this body is what the
    # API's dependency poll parses.
    test "carries no build identity" do
      start_health()

      body = Jason.decode!(call(:get, "/ready", %{}, token: nil).resp_body)

      refute Map.has_key?(body, "revision")
      refute Map.has_key?(body, "version")
    end

    # The route is unauthenticated, so the body is the blast radius. It must not
    # name the key, the account, the region, or the AWS failure.
    test "reveals nothing about KMS beyond the bare status" do
      put_relayer_key("secret-relayer-key-id")
      start_health()
      assert Health.check_now() == :error

      body = call(:get, "/ready", %{}, token: nil).resp_body

      refute body =~ "secret-relayer-key-id"
      refute body =~ "FunctionClauseError"
      refute body =~ "arn"
      refute body =~ "region"
    end

    test "a non-GET /ready still requires the token" do
      assert call(:post, "/ready", %{}, token: nil).status == 401
      assert call(:post, "/ready", %{}).status == 404
    end
  end

  test "rejects a request with no bearer token" do
    conn = call(:post, "/v1/sign", %{}, token: nil)
    assert conn.status == 401
  end

  test "rejects a request with the wrong bearer token" do
    conn = call(:post, "/v1/sign", %{}, token: "nope")
    assert conn.status == 401
  end

  test "creates a key then signs a digest that verifies against it" do
    conn = call(:post, "/v1/keys", %{holder_id: "workspace_1_signing"})
    assert conn.status == 201

    %{"key_id" => key_id, "public_key_x" => x_hex, "public_key_y" => y_hex} =
      Jason.decode!(conn.resp_body)

    x = Base.decode16!(x_hex, case: :lower)
    y = Base.decode16!(y_hex, case: :lower)

    digest = :crypto.hash(:sha256, "payload")
    conn = call(:post, "/v1/sign", %{key: key_id, digest: Base.encode16(digest, case: :lower)})
    assert conn.status == 200
    %{"r" => r_hex, "s" => s_hex} = Jason.decode!(conn.resp_body)
    r = Base.decode16!(r_hex, case: :lower)
    s = Base.decode16!(s_hex, case: :lower)

    assert P256.verify(digest, %{r: r, s: s}, {x, y})
  end

  test "a malformed digest is a 400, not a crash" do
    conn = call(:post, "/v1/sign", %{key: "stub-00", digest: "zz"})
    assert conn.status == 400
  end

  test "a non-string holder_id is a 400, not a crash" do
    conn = call(:post, "/v1/keys", %{holder_id: 123})
    assert conn.status == 400
    assert %{"error" => "invalid_holder_id"} = Jason.decode!(conn.resp_body)
  end

  test "a missing holder_id defaults to empty and still creates a key" do
    conn = call(:post, "/v1/keys", %{})
    assert conn.status == 201
  end

  test "an unknown route is a 404" do
    conn = call(:get, "/nope", %{})
    assert conn.status == 404
  end

  test "relayer/sign returns a recoverable secp256k1 signature" do
    digest = :crypto.hash(:sha256, "an ethereum tx hash")
    conn = call(:post, "/v1/relayer/sign", %{digest: Base.encode16(digest, case: :lower)})
    assert conn.status == 200
    %{"r" => r_hex, "s" => s_hex, "recovery_id" => v} = Jason.decode!(conn.resp_body)
    r = Base.decode16!(r_hex, case: :lower)
    s = Base.decode16!(s_hex, case: :lower)

    {:ok, pub} = ExSecp256k1.create_public_key(String.duplicate(<<0x11>>, 32))
    assert v in [0, 1]
    assert {:ok, ^pub} = ExSecp256k1.recover(digest, r, s, v)
  end

  test "relayer/address returns the relayer's 0x address" do
    {:ok, pub} = ExSecp256k1.create_public_key(String.duplicate(<<0x11>>, 32))

    conn =
      conn(:get, "/v1/relayer/address")
      |> put_req_header("authorization", "Bearer " <> @token)
      |> Router.call(@opts)

    assert conn.status == 200
    assert %{"address" => address} = Jason.decode!(conn.resp_body)
    assert address == Ethers.Utils.public_key_to_address(pub)
  end

  defp start_health, do: start_supervised!({Health, enabled: true, interval_ms: 60_000})

  # String-keyed, to merge into the expected bodies above.
  defp build_fields, do: Map.new(BuildInfo.all(), fn {key, value} -> {to_string(key), value} end)

  defp put_relayer_key(key_id) do
    config = Application.get_env(:sovra, :signer_service, [])
    on_exit(fn -> Application.put_env(:sovra, :signer_service, config) end)
    Application.put_env(:sovra, :signer_service, Keyword.put(config, :relayer_kms_key_id, key_id))
  end
end
