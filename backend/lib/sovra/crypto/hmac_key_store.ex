defmodule Sovra.Crypto.HmacKeyStore do
  @moduledoc """
  Behaviour for HMAC-SHA256 secret storage backends.

  Implementations:
  - `Sovra.Crypto.DatabaseHmacStore` — all environments. The webhook secret is
    revealed to the customer exactly once (at creation/rotation) so they can
    verify our signatures, and AWS KMS HMAC keys are non-exportable — so unlike
    the P-256 signing keys this secret cannot live in KMS. It is stored in the
    `stored_keys` table (encrypted at rest by `Sovra.Crypto.StoredKeyCipher`)
    and HMAC is computed locally with `:crypto.mac/3`.
  """

  @doc """
  Generate a fresh HMAC key and return its opaque identifier plus the plaintext
  (so the caller can reveal it to the user exactly once).
  """
  @callback generate_hmac_key() ::
              {:ok, %{key_id: String.t(), plaintext: String.t()}} | {:error, term()}

  @doc """
  Compute HMAC-SHA256 over `payload` using the key referenced by `key_id`.
  Returns the raw 32-byte signature.
  """
  @callback hmac(key_id :: String.t(), payload :: iodata()) ::
              {:ok, binary()} | {:error, term()}

  @doc """
  Rotate the key referenced by `key_id`. Returns the new plaintext (so the
  caller can reveal it to the user exactly once).
  """
  @callback rotate(key_id :: String.t()) ::
              {:ok, %{plaintext: String.t()}} | {:error, term()}

  @doc """
  Delete the key entirely. Called when a workspace is deactivated/deleted.
  """
  @callback delete(key_id :: String.t()) :: :ok | {:error, term()}

  @doc "Resolves the configured HMAC key store module."
  def impl, do: Application.fetch_env!(:sovra, :hmac_key_store)

  def generate_hmac_key, do: impl().generate_hmac_key()
  def hmac(key_id, payload), do: impl().hmac(key_id, payload)
  def rotate(key_id), do: impl().rotate(key_id)
  def delete(key_id), do: impl().delete(key_id)
end
