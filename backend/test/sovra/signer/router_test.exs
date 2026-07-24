defmodule Sovra.Signer.RouterTest do
  use ExUnit.Case, async: true

  import Plug.Test
  import Plug.Conn

  alias Sovra.Crypto.P256
  alias Sovra.Signer.Router

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
end
