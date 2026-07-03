defmodule Sovra.DID.SovraMethod do
  @moduledoc """
  did:sovra method resolver.

  A Sovra DID has the form `did:sovra:0x<eoa>` where `<eoa>` is the
  40-character lowercase hex Ethereum address of the holder's wallet
  contract. Resolving the DID means reading that contract's current
  signing key(s) on-chain, so the resolver always returns the holder's
  *currently* authorized key(s), never the one frozen at issuance time.

  Two on-chain sources, selected by `config :sovra, :did, identity_source:`:

    * `:legacy` (default) — the custom `SovraWalletV1` contract; one P-256
      passkey rotated in place by the guardian-cosigned recovery flow.
    * `:aligned` — an `AlignedAccount` contract; the holder's active
      `WebAuthnP256` user keys (multiple keys supported).

  Returns a JWK list.
  """

  alias Sovra.Ethereum.WalletReader

  @typedoc "Single-method DID resolution result. JWK fields hold raw 32-byte coordinates."
  @type jwk :: %{kty: String.t(), crv: String.t(), x: binary, y: binary}

  @spec resolve(String.t()) :: {:ok, [jwk]} | {:error, atom}
  def resolve("did:sovra:" <> rest) do
    case parse_eoa(rest) do
      {:ok, eoa} ->
        case identity_source() do
          :aligned -> resolve_aligned(eoa)
          _ -> resolve_legacy(eoa)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  def resolve(_), do: {:error, :unsupported_did_method}

  defp resolve_aligned(eoa) do
    case WalletReader.read_aligned_keys(eoa) do
      {:ok, keys} ->
        {:ok, Enum.map(keys, fn {x, y} -> %{kty: "EC", crv: "P-256", x: x, y: y} end)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp resolve_legacy(eoa) do
    with {:ok, false} <- WalletReader.did_deactivated?(eoa),
         {:ok, {x, y}} <- WalletReader.read_passkey(eoa) do
      {:ok, [%{kty: "EC", crv: "P-256", x: x, y: y}]}
    else
      {:ok, true} -> {:error, :did_deactivated}
      {:error, reason} -> {:error, reason}
    end
  end

  defp identity_source do
    Application.get_env(:sovra, :did, []) |> Keyword.get(:identity_source, :legacy)
  end

  defp parse_eoa("0x" <> hex = full) when byte_size(hex) == 40 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, _} -> {:ok, full}
      _ -> {:error, :invalid_did}
    end
  end

  defp parse_eoa(_), do: {:error, :invalid_did}
end
