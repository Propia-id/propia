defmodule Sovra.Crypto.Spki do
  @moduledoc """
  SubjectPublicKeyInfo parsing shared by the P-256 and secp256k1 KMS paths.

  AWS KMS `GetPublicKey` returns the public key as DER-encoded SPKI; for both
  curves the key material is the 65-byte uncompressed EC point
  (`04 || X || Y`, 32-byte coordinates).
  """

  @doc "Extract the 65-byte uncompressed point (04||X||Y) from a DER SPKI."
  @spec uncompressed_point(binary()) :: {:ok, <<_::520>>} | {:error, :invalid_public_key_format}
  def uncompressed_point(der) do
    case :public_key.der_decode(:SubjectPublicKeyInfo, der) do
      {:SubjectPublicKeyInfo, _algo, <<4, _::binary-size(64)>> = point} -> {:ok, point}
      _ -> {:error, :invalid_public_key_format}
    end
  rescue
    _ -> {:error, :invalid_public_key_format}
  end
end
