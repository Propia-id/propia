defmodule Sovra.DID.SovraMethod do
  @moduledoc """
  did:sovra method resolver.

  A Sovra DID has the form `did:sovra:0x<eoa>` where `<eoa>` is the
  40-character lowercase hex Ethereum address of the holder's
  EIP-7702-delegated wallet contract. Resolving the DID means reading
  the wallet contract's current passkey on-chain — that key is rotated
  in place by the guardian-cosigned recovery flow, so the resolver
  always returns the holder's *currently* authorized signing key, never
  the one frozen at issuance time.

  Returns a JWK list because future methods may publish multiple keys;
  today it always contains exactly one entry.
  """

  alias Sovra.Ethereum.WalletReader

  @typedoc "Single-method DID resolution result. JWK fields hold raw 32-byte coordinates."
  @type jwk :: %{kty: String.t(), crv: String.t(), x: binary, y: binary}

  @spec resolve(String.t()) :: {:ok, [jwk]} | {:error, atom}
  def resolve("did:sovra:" <> rest) do
    with {:ok, eoa} <- parse_eoa(rest),
         {:ok, false} <- WalletReader.did_deactivated?(eoa),
         {:ok, {x, y}} <- WalletReader.read_passkey(eoa) do
      {:ok, [%{kty: "EC", crv: "P-256", x: x, y: y}]}
    else
      {:ok, true} -> {:error, :did_deactivated}
      {:error, reason} -> {:error, reason}
    end
  end

  def resolve(_), do: {:error, :unsupported_did_method}

  defp parse_eoa("0x" <> hex = full) when byte_size(hex) == 40 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, _} -> {:ok, full}
      _ -> {:error, :invalid_did}
    end
  end

  defp parse_eoa(_), do: {:error, :invalid_did}
end
