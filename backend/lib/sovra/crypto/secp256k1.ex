defmodule Sovra.Crypto.Secp256k1 do
  @moduledoc """
  secp256k1 helpers for the KMS relayer path (distinct curve from
  `Sovra.Crypto.P256`, which is secp256r1):

    * `parse_der/1` — a KMS DER ECDSA signature → 32-byte `{r, s}`, low-s
      normalized (EIP-2).
    * `recovery_id/4` — Ethereum's recovery id (0/1) for a signature over a
      digest, found by matching the relayer's known public key.
    * `address/1` — the checksummed 0x address for a 65-byte uncompressed point.

  SPKI parsing lives in `Sovra.Crypto.Spki` (shared with the P-256 path).
  """

  alias Sovra.Crypto.Ecdsa

  # secp256k1 group order (EIP-2 low-s normalization).
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  @doc "Parse a DER ECDSA signature into 32-byte `{r, s}`, low-s normalized."
  @spec parse_der(binary()) :: {:ok, {binary(), binary()}} | {:error, term()}
  def parse_der(der), do: Ecdsa.parse_der_signature(der, @n)

  @doc "Recover Ethereum's recovery id (0/1) for `{r, s}` over `hash`."
  @spec recovery_id(<<_::256>>, binary(), binary(), binary()) :: {:ok, 0 | 1} | {:error, term()}
  def recovery_id(<<hash::binary-size(32)>>, r, s, expected_pub) do
    want = body(expected_pub)

    Enum.find_value(0..1, {:error, :recovery_failed}, fn v ->
      case ExSecp256k1.recover(hash, r, s, v) do
        {:ok, pub} -> if body(pub) == want, do: {:ok, v}, else: false
        _ -> false
      end
    end)
  end

  @doc "Checksummed 0x address for a 65-byte uncompressed public key."
  @spec address(<<_::520>>) :: String.t()
  def address(<<_::binary-size(65)>> = pub), do: Ethers.Utils.public_key_to_address(pub)

  # --- internals -------------------------------------------------------------

  defp body(<<4, b::binary-size(64)>>), do: b
  defp body(<<b::binary-size(64)>>), do: b
end
