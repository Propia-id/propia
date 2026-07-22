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

  describe "verify/3 signature malleability (low-S enforcement)" do
    # P-256 curve order
    @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    test "rejects the high-S form of an otherwise-valid signature" do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
      hash = :crypto.strong_rand_bytes(32)

      # sign/2 already normalizes to low-S, so this is the canonical signature.
      {:ok, %{r: r, s: s} = low_s_sig} = P256.sign(hash, priv)

      # The canonical low-S form verifies.
      assert P256.verify(hash, low_s_sig, {x, y})

      # Flip to the malleable high-S form: s' = n - s. This is the *same*
      # ECDSA signature mathematically, so a naive verify would accept it.
      high_s = (@n - :binary.decode_unsigned(s)) |> :binary.encode_unsigned() |> pad32()
      high_s_sig = %{r: r, s: high_s}

      # Sanity: the mutation actually produced the high half (s' > n/2).
      assert :binary.decode_unsigned(high_s) > div(@n, 2)

      # verify/3 must reject it on the low-S guard, before the ECDSA check.
      refute P256.verify(hash, high_s_sig, {x, y})
    end
  end

  defp pad32(bin) when byte_size(bin) == 32, do: bin

  defp pad32(bin) when byte_size(bin) < 32,
    do: <<0::size((32 - byte_size(bin)) * 8), bin::binary>>
end
