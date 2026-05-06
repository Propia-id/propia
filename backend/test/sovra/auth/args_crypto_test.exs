defmodule Sovra.Auth.ArgsCryptoTest do
  use ExUnit.Case, async: true

  alias Sovra.Auth.ArgsCrypto

  test "encrypt/decrypt roundtrip preserves the plaintext" do
    plaintext = "a-secret-32-byte-token-#{System.unique_integer([:positive])}"

    encrypted = ArgsCrypto.encrypt(plaintext)
    assert is_binary(encrypted)
    refute String.contains?(encrypted, plaintext)

    assert {:ok, ^plaintext} = ArgsCrypto.decrypt(encrypted)
  end

  test "encrypt/1 produces different ciphertexts for the same plaintext (random IV)" do
    plaintext = "deterministic input"
    a = ArgsCrypto.encrypt(plaintext)
    b = ArgsCrypto.encrypt(plaintext)

    refute a == b
    assert {:ok, ^plaintext} = ArgsCrypto.decrypt(a)
    assert {:ok, ^plaintext} = ArgsCrypto.decrypt(b)
  end

  test "decrypt/1 returns :error on tampering" do
    encrypted = ArgsCrypto.encrypt("secret")

    # Flip one bit in the middle of the ciphertext.
    flipped =
      encrypted
      |> String.replace_prefix("A", "B")
      |> String.replace_prefix("B", "A")
      |> case do
        ^encrypted -> "X" <> String.slice(encrypted, 1..-1//1)
        other -> other
      end

    assert :error = ArgsCrypto.decrypt(flipped)
  end

  test "decrypt/1 returns :error on garbage input" do
    assert :error = ArgsCrypto.decrypt("not-valid-base64!!")
    assert :error = ArgsCrypto.decrypt("")
    # Valid base64 but too short to even contain IV+tag
    assert :error = ArgsCrypto.decrypt(Base.url_encode64("short", padding: false))
  end
end
