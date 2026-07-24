defmodule Sovra.Crypto.SpkiTest do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.Spki

  # SPKI headers up to the BIT STRING unused-bits octet (same shapes AWS KMS
  # returns; see SovraTest.Crypto.StubKms).
  @p256_spki Base.decode16!("3059301306072A8648CE3D020106082A8648CE3D030107034200")
  @k1_spki Base.decode16!("3056301006072A8648CE3D020106052B8104000A034200")

  test "extracts the 65-byte uncompressed point for both curves" do
    for {curve, prefix} <- [{:secp256r1, @p256_spki}, {:secp256k1, @k1_spki}] do
      {pub, _priv} = :crypto.generate_key(:ecdh, curve)

      assert {:ok, ^pub} = Spki.uncompressed_point(prefix <> pub)
      assert <<4, _::binary-size(64)>> = pub
    end
  end

  test "rejects garbage that is not DER" do
    assert {:error, :invalid_public_key_format} = Spki.uncompressed_point(<<1, 2, 3>>)
  end
end
