defmodule Sovra.Signer.RelayerTest do
  use ExUnit.Case, async: true

  alias Sovra.Signer.Relayer

  # config/test.exs sets relayer_kms_key_id = "stub-k1-" <> 0x11*32; StubKms
  # signs/derives with that secp256k1 private key.
  @priv String.duplicate(<<0x11>>, 32)

  # secp256k1 group order (for the low-s assertion).
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  test "address matches the relayer key" do
    {:ok, pub} = ExSecp256k1.create_public_key(@priv)
    assert {:ok, address} = Relayer.address()
    assert address == Ethers.Utils.public_key_to_address(pub)
  end

  test "sign returns a low-s secp256k1 signature that recovers the relayer key" do
    {:ok, pub} = ExSecp256k1.create_public_key(@priv)
    digest = :crypto.hash(:sha256, "on-chain tx")

    assert {:ok, %{r: r, s: s, recovery_id: v}} = Relayer.sign(digest)
    assert byte_size(r) == 32 and byte_size(s) == 32
    assert v in [0, 1]
    assert {:ok, ^pub} = ExSecp256k1.recover(digest, r, s, v)
    assert :binary.decode_unsigned(s) <= div(@n, 2)
  end

  test "sign rejects a digest that is not 32 bytes" do
    assert {:error, :invalid_hash_size} = Relayer.sign(<<1, 2, 3>>)
  end
end
