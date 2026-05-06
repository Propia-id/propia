defmodule Sovra.Crypto.JwtSigner do
  @moduledoc """
  ES256 (P-256) compact-JWS signer. Used for SD-JWT credentials and W3C
  BitstringStatusListCredential JWTs.

  Signature is raw `r||s` (64 bytes) per RFC 7515 §3.4 — not the DER form.
  """

  alias Sovra.Crypto.Key
  alias Sovra.Crypto.P256

  @doc """
  Sign `header` and `payload` (each a JSON-encodable map) with the P-256 key
  referenced by `signing_key_id`. Returns the compact JWS `header.payload.sig`.
  """
  @spec sign(map(), map(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def sign(header, payload, signing_key_id) do
    signing_input = encode_signing_input(header, payload)

    case sign_signing_input(signing_input, signing_key_id) do
      {:ok, sig_b64} -> {:ok, "#{signing_input}.#{sig_b64}"}
      {:error, _} = error -> error
    end
  end

  @doc """
  Encode `header.payload` as the JWS signing input. Lets callers compute a
  cheap content hash (e.g. for an HTTP ETag) before paying for a signature.
  """
  @spec encode_signing_input(map(), map()) :: String.t()
  def encode_signing_input(header, payload) do
    header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
    payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
    "#{header_b64}.#{payload_b64}"
  end

  @doc """
  Sign a pre-encoded signing input. Returns the base64url-encoded `r||s`
  signature segment (no leading dot). Use together with
  `encode_signing_input/2` to defer signing until after a 304-on-ETag check.
  """
  @spec sign_signing_input(String.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def sign_signing_input(signing_input, signing_key_id) do
    hash = :crypto.hash(:sha256, signing_input)

    case Key.sign(signing_key_id, hash) do
      {:ok, %{r: r, s: s}} ->
        raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
        {:ok, Base.url_encode64(raw_sig, padding: false)}

      {:error, _} = error ->
        error
    end
  end
end
