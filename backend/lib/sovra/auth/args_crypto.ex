defmodule Sovra.Auth.ArgsCrypto do
  @moduledoc """
  AES-256-GCM symmetric encryption for sensitive values placed in
  durable storage we don't want to land in DB backups (notably,
  `oban_jobs.args` for transactional emails that carry secrets).

  Output format: Base64(IV ‖ TAG ‖ CIPHERTEXT) where IV is 12 bytes
  and TAG is 16 bytes. Keys are derived per-purpose via
  `Sovra.Auth.KeyDerivation`, so a leak of one subsystem's data
  doesn't compromise another.
  """

  alias Sovra.Auth.KeyDerivation

  @iv_bytes 12
  @tag_bytes 16
  # `aad` is empty: every ciphertext is bound to its 256-bit key plus its
  # random IV, which is sufficient for our threat model (encrypt-at-rest of
  # short-lived secrets in oban_jobs.args).
  @aad ""

  @doc "Encrypt a UTF-8 binary. Returns a Base64-encoded ciphertext."
  @spec encrypt(binary()) :: binary()
  def encrypt(plaintext) when is_binary(plaintext) do
    key = KeyDerivation.derive_key(:oban_args)
    iv = :crypto.strong_rand_bytes(@iv_bytes)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, plaintext, @aad, @tag_bytes, true)

    Base.url_encode64(iv <> tag <> ciphertext, padding: false)
  end

  @doc "Decrypt a value produced by `encrypt/1`. Returns `{:ok, plaintext}` or `:error`."
  @spec decrypt(binary()) :: {:ok, binary()} | :error
  def decrypt(encoded) when is_binary(encoded) do
    with {:ok, raw} <- Base.url_decode64(encoded, padding: false),
         <<iv::binary-size(@iv_bytes), tag::binary-size(@tag_bytes), ciphertext::binary>> <- raw do
      key = KeyDerivation.derive_key(:oban_args)

      case :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             key,
             iv,
             ciphertext,
             @aad,
             tag,
             false
           ) do
        plaintext when is_binary(plaintext) -> {:ok, plaintext}
        _ -> :error
      end
    else
      _ -> :error
    end
  rescue
    _ -> :error
  end
end
