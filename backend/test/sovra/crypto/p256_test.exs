defmodule Sovra.Crypto.P256Test do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.P256

  describe "generate_key_pair/0" do
    test "returns 32-byte x and y coordinates and a private key" do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

      assert byte_size(x) == 32
      assert byte_size(y) == 32
      assert is_binary(priv)
    end

    test "generates unique keys" do
      {:ok, key1} = P256.generate_key_pair()
      {:ok, key2} = P256.generate_key_pair()

      refute key1.private_key == key2.private_key
    end
  end

  describe "sign/2 and verify/3" do
    test "sign/verify round-trip succeeds" do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
      hash = :crypto.strong_rand_bytes(32)

      {:ok, %{r: r, s: s}} = P256.sign(hash, priv)

      assert byte_size(r) == 32
      assert byte_size(s) == 32
      assert P256.verify(hash, %{r: r, s: s}, {x, y})
    end

    test "verify rejects tampered hash" do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
      hash = :crypto.strong_rand_bytes(32)
      tampered = :crypto.strong_rand_bytes(32)

      {:ok, sig} = P256.sign(hash, priv)

      refute P256.verify(tampered, sig, {x, y})
    end

    test "verify rejects wrong public key" do
      {:ok, key1} = P256.generate_key_pair()
      {:ok, key2} = P256.generate_key_pair()
      hash = :crypto.strong_rand_bytes(32)

      {:ok, sig} = P256.sign(hash, key1.private_key)

      refute P256.verify(hash, sig, {key2.public_key_x, key2.public_key_y})
    end

    test "sign rejects non-32-byte hash" do
      {:ok, %{private_key: priv}} = P256.generate_key_pair()

      assert {:error, :invalid_hash_size} = P256.sign(<<1, 2, 3>>, priv)
      assert {:error, :invalid_hash_size} = P256.sign(:crypto.strong_rand_bytes(64), priv)
    end
  end
end
