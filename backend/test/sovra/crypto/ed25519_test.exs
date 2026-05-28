defmodule Sovra.Crypto.Ed25519Test do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.Ed25519

  describe "verify/3" do
    test "RFC 8032 §7.1 Test 1 — empty message" do
      # https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
      pub =
        Base.decode16!(
          "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
          case: :lower
        )

      sig =
        Base.decode16!(
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
          case: :lower
        )

      assert Ed25519.verify("", sig, pub)
    end

    test "RFC 8032 §7.1 Test 2 — single-byte message" do
      pub =
        Base.decode16!(
          "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
          case: :lower
        )

      sig =
        Base.decode16!(
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
          case: :lower
        )

      assert Ed25519.verify(<<0x72>>, sig, pub)
    end

    test "round-trip with a freshly generated keypair" do
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      message = "hello world"
      signature = :crypto.sign(:eddsa, :none, message, [priv, :ed25519])

      assert Ed25519.verify(message, signature, pub)
    end

    test "rejects a flipped bit in the signature" do
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      message = "hello world"
      <<first, rest::binary>> = :crypto.sign(:eddsa, :none, message, [priv, :ed25519])
      tampered = <<Bitwise.bxor(first, 0x01), rest::binary>>

      refute Ed25519.verify(message, tampered, pub)
    end

    test "rejects mismatched message" do
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      signature = :crypto.sign(:eddsa, :none, "original", [priv, :ed25519])

      refute Ed25519.verify("different", signature, pub)
    end

    test "returns false for wrong-size signature" do
      {pub, _priv} = :crypto.generate_key(:eddsa, :ed25519)
      refute Ed25519.verify("msg", <<0::8>>, pub)
    end

    test "returns false for wrong-size public key" do
      refute Ed25519.verify("msg", :crypto.strong_rand_bytes(64), <<0::8>>)
    end

    test "returns false for non-binary inputs" do
      refute Ed25519.verify(nil, nil, nil)
    end
  end
end
