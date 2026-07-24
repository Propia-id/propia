defmodule Sovra.Crypto.KmsKeyStoreTest do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.KmsKeyStore

  # config/test.exs points :sovra, :signer at a Req.Test plug (:sovra_signer),
  # so these stubs intercept the HTTP the store makes to the signer service.

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, Jason.encode!(body))
  end

  test "generate_key posts /v1/keys and decodes the coordinates" do
    x = :crypto.strong_rand_bytes(32)
    y = :crypto.strong_rand_bytes(32)

    Req.Test.stub(:sovra_signer, fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/v1/keys"

      json(conn, 201, %{
        key_id: "kms-123",
        public_key_x: Base.encode16(x, case: :lower),
        public_key_y: Base.encode16(y, case: :lower)
      })
    end)

    assert {:ok, %{key_id: "kms-123", public_key_x: ^x, public_key_y: ^y}} =
             KmsKeyStore.generate_key("holder-1")
  end

  test "sign posts the hex digest and decodes {r, s}" do
    r = :crypto.strong_rand_bytes(32)
    s = :crypto.strong_rand_bytes(32)
    hash = :crypto.hash(:sha256, "x")

    Req.Test.stub(:sovra_signer, fn conn ->
      assert conn.request_path == "/v1/sign"

      json(conn, 200, %{r: Base.encode16(r, case: :lower), s: Base.encode16(s, case: :lower)})
    end)

    assert {:ok, %{r: ^r, s: ^s}} = KmsKeyStore.sign("kms-123", hash)
  end

  test "sign rejects a non-32-byte hash without calling the signer" do
    assert {:error, :invalid_hash_size} = KmsKeyStore.sign("kms-123", <<1, 2, 3>>)
  end

  test "delete_key hits the deletion endpoint" do
    Req.Test.stub(:sovra_signer, fn conn ->
      assert conn.request_path == "/v1/keys/kms-123/deletion"
      json(conn, 200, %{status: "scheduled"})
    end)

    assert :ok = KmsKeyStore.delete_key("kms-123")
  end

  test "surfaces a signer error status" do
    Req.Test.stub(:sovra_signer, fn conn -> json(conn, 502, %{error: "kms_down"}) end)

    assert {:error, {:signer_error, 502, _body}} =
             KmsKeyStore.sign("kms-123", :crypto.hash(:sha256, "x"))
  end

  test "a wrong-length public-key coordinate is a clean error, not a crash" do
    Req.Test.stub(:sovra_signer, fn conn ->
      json(conn, 201, %{
        key_id: "kms-123",
        public_key_x: Base.encode16(:crypto.strong_rand_bytes(31), case: :lower),
        public_key_y: Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
      })
    end)

    assert {:error, {:unexpected_signer_response, _}} = KmsKeyStore.generate_key("holder-1")
  end

  test "a wrong-length signature component is a clean error, not a crash" do
    Req.Test.stub(:sovra_signer, fn conn ->
      json(conn, 200, %{
        r: Base.encode16(:crypto.strong_rand_bytes(33), case: :lower),
        s: Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
      })
    end)

    assert {:error, {:unexpected_signer_response, _}} =
             KmsKeyStore.sign("kms-123", :crypto.hash(:sha256, "x"))
  end
end
