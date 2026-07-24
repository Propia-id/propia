defmodule Sovra.Crypto.StoredKeyCipher do
  @moduledoc """
  At-rest encryption for secret values in the `stored_keys` table.

  AES-256-GCM with the 32-byte key from `config :sovra,
  :stored_keys_encryption_key` (`STORED_KEYS_ENCRYPTION_KEY` in prod, fixed
  insecure constants in dev/test). The row's `key_id` is bound as AAD so a
  ciphertext cannot be moved onto another row. Stored layout:
  `"SKC1" <> iv(12) <> tag(16) <> ciphertext`.

  Values without the `"SKC1"` prefix are legacy rows written before encryption
  was introduced; `decrypt/2` returns them unchanged so existing workspaces
  keep signing. Rotation re-encrypts.
  """

  @magic "SKC1"
  @iv_bytes 12
  @tag_bytes 16

  @spec encrypt(binary(), String.t()) :: binary()
  def encrypt(plaintext, key_id) when is_binary(plaintext) and is_binary(key_id) do
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key!(), iv, plaintext, key_id, true)

    @magic <> iv <> tag <> ciphertext
  end

  @spec decrypt(binary(), String.t()) :: {:ok, binary()} | {:error, :decrypt_failed}
  def decrypt(
        <<@magic, iv::binary-size(@iv_bytes), tag::binary-size(@tag_bytes), ciphertext::binary>>,
        key_id
      ) do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key!(), iv, ciphertext, key_id, tag, false) do
      :error -> {:error, :decrypt_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  # Legacy plaintext row written before at-rest encryption existed.
  def decrypt(plaintext, _key_id) when is_binary(plaintext), do: {:ok, plaintext}

  defp key! do
    key = Application.fetch_env!(:sovra, :stored_keys_encryption_key)

    byte_size(key) == 32 ||
      raise ArgumentError, "config :sovra, :stored_keys_encryption_key must be exactly 32 bytes"

    key
  end
end
