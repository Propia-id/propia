defmodule Sovra.Ethereum.WalletReaderTest do
  use ExUnit.Case, async: true

  alias Sovra.Ethereum.WalletReader

  describe "decode_aligned_key/1" do
    test "decodes a WebAuthnP256 Key struct return" do
      x = :crypto.strong_rand_bytes(32)
      y = :crypto.strong_rand_bytes(32)
      valid_at = 1_700_000_000

      # ABI return of `getUserKeyByHash` → Key { uint8 keyType; uint48 validAt;
      # bytes publicKey }: offset(0x20), keyType, validAt, bytes-offset(0x60),
      # len(64), then x||y.
      raw =
        <<0x20::256, 2::256, valid_at::256, 0x60::256, 64::256>> <> x <> y

      assert {:ok, {2, ^valid_at, {^x, ^y}}} = WalletReader.decode_aligned_key(raw)
    end

    test "rejects a publicKey that isn't 64 bytes" do
      raw = <<0x20::256, 2::256, 0::256, 0x60::256, 32::256, 0::256>>
      assert {:error, :malformed_key} = WalletReader.decode_aligned_key(raw)
    end

    test "rejects truncated data" do
      assert {:error, :malformed_key} = WalletReader.decode_aligned_key(<<0, 1, 2>>)
    end
  end

  describe "decode_call_body/1" do
    test "decodes a 32-byte word" do
      assert {:ok, <<1::256>>} =
               WalletReader.decode_call_body("0x" <> Base.encode16(<<1::256>>, case: :lower))
    end

    # Not {:ok, 0}: nonce 0 would go on to be signed into an EIP-712 hash.
    test "rejects an empty result" do
      assert {:error, :empty_response} = WalletReader.decode_call_body("0x")
    end

    test "rejects a null result" do
      assert {:error, :malformed_response} = WalletReader.decode_call_body(nil)
    end

    test "rejects a non-hex result" do
      assert {:error, :malformed_response} = WalletReader.decode_call_body("0xzz")
    end
  end
end
