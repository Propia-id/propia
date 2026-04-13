defmodule Sovra.Crypto.VaultKeyStoreTest do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.P256

  describe "DER parsing (unit)" do
    test "parse_der_signature extracts and normalizes r, s from a DER signature" do
      {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
      hash = :crypto.strong_rand_bytes(32)
      der = :crypto.sign(:ecdsa, :sha256, {:digest, hash}, [priv, :secp256r1])

      {:ok, %{r: r, s: s}} = P256.parse_der_signature(der)

      assert byte_size(r) == 32
      assert byte_size(s) == 32

      <<4, x::binary-size(32), y::binary-size(32)>> = pub
      assert P256.verify(hash, %{r: r, s: s}, {x, y})
    end

    test "PEM public key parsing extracts correct coordinates" do
      {pub, _priv} = :crypto.generate_key(:ecdh, :secp256r1)
      <<4, expected_x::binary-size(32), expected_y::binary-size(32)>> = pub

      # Build SubjectPublicKeyInfo DER (fixed prefix for P-256)
      spki_prefix =
        <<0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
          0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00>>

      spki_der = spki_prefix <> pub

      # Wrap as PEM (what Transit returns)
      pem = :public_key.pem_encode([{:SubjectPublicKeyInfo, spki_der, :not_encrypted}])

      # Parse like VaultKeyStore does
      [{:SubjectPublicKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)

      {:SubjectPublicKeyInfo, _algo, key_bits} =
        :public_key.der_decode(:SubjectPublicKeyInfo, der)

      <<4, x::binary-size(32), y::binary-size(32)>> = key_bits

      assert x == expected_x
      assert y == expected_y
    end

    test "vault signature prefix stripping" do
      {_pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
      hash = :crypto.strong_rand_bytes(32)
      der = :crypto.sign(:ecdsa, :sha256, {:digest, hash}, [priv, :secp256r1])

      # Simulate vault:v1:<base64> format
      vault_sig = "vault:v1:" <> Base.encode64(der)

      "vault:v1:" <> b64 = vault_sig
      parsed_der = Base.decode64!(b64)
      {:ok, %{r: r, s: s}} = P256.parse_der_signature(parsed_der)

      assert byte_size(r) == 32
      assert byte_size(s) == 32
    end
  end

  describe "VaultKeyStore integration (requires OpenBao)" do
    @describetag :skip

    test "generate_key → sign → delete lifecycle" do
      alias Sovra.Crypto.VaultKeyStore

      {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
        VaultKeyStore.generate_key("holder-vault")

      assert is_binary(key_id)
      assert byte_size(x) == 32
      assert byte_size(y) == 32

      hash = :crypto.strong_rand_bytes(32)
      {:ok, %{r: r, s: s}} = VaultKeyStore.sign(key_id, hash)

      assert P256.verify(hash, %{r: r, s: s}, {x, y})

      assert :ok = VaultKeyStore.delete_key(key_id)
    end
  end
end
