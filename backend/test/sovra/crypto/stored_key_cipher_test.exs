defmodule Sovra.Crypto.StoredKeyCipherTest do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.StoredKeyCipher

  @key_id "webhook-abc123"
  @plaintext "whsec_" <> Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

  test "round-trips plaintext" do
    ciphertext = StoredKeyCipher.encrypt(@plaintext, @key_id)

    assert ciphertext != @plaintext
    refute String.contains?(ciphertext, @plaintext)
    assert {:ok, @plaintext} = StoredKeyCipher.decrypt(ciphertext, @key_id)
  end

  test "binds the ciphertext to its key_id" do
    ciphertext = StoredKeyCipher.encrypt(@plaintext, @key_id)

    assert {:error, :decrypt_failed} = StoredKeyCipher.decrypt(ciphertext, "webhook-other")
  end

  test "rejects tampered ciphertext" do
    <<prefix::binary-size(32), byte, rest::binary>> = StoredKeyCipher.encrypt(@plaintext, @key_id)
    tampered = <<prefix::binary, Bitwise.bxor(byte, 1), rest::binary>>

    assert {:error, :decrypt_failed} = StoredKeyCipher.decrypt(tampered, @key_id)
  end

  test "passes legacy plaintext rows through unchanged" do
    assert {:ok, @plaintext} = StoredKeyCipher.decrypt(@plaintext, @key_id)
  end

  test "encrypting twice yields distinct ciphertexts (fresh IV)" do
    assert StoredKeyCipher.encrypt(@plaintext, @key_id) !=
             StoredKeyCipher.encrypt(@plaintext, @key_id)
  end
end
