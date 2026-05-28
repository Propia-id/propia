defmodule Sovra.Crypto.Ed25519 do
  @moduledoc """
  Ed25519 signature verification using Erlang `:crypto`.

  Unlike ECDSA over P-256, Ed25519 verifies the raw message — callers must
  pass the JWT `signing_input` directly, not its SHA-256 digest. The
  signature is the raw 64-byte R||S concatenation that JOSE uses for `EdDSA`.
  """

  @pub_key_size 32
  @signature_size 64

  @doc """
  Verify an Ed25519 signature over `message` with a raw 32-byte public key.

  Returns `true` if the signature verifies, `false` otherwise (including for
  any malformed input — never raises).
  """
  @spec verify(binary, binary, binary) :: boolean
  def verify(message, signature, public_key)
      when is_binary(message) and byte_size(signature) == @signature_size and
             byte_size(public_key) == @pub_key_size do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  rescue
    _ -> false
  end

  def verify(_, _, _), do: false
end
