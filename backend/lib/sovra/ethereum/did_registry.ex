defmodule Sovra.Ethereum.DIDRegistry do
  @moduledoc """
  Smart contract interaction for SovraDIDRegistry.
  Manages on-chain DID documents for issuers and verifiers.
  """

  alias Sovra.Ethereum.Client
  alias Sovra.Ethereum.Contracts.DIDRegistryContract

  @doc """
  Register an issuer DID on-chain with their P-256 signing key and OID4VCI service endpoint.

  - `issuer_eoa` — the identity address (0x-prefixed hex string)
  - `pub_key_x`, `pub_key_y` — 32-byte binaries of the P-256 public key
  - `service_endpoint` — OID4VCI base URL string
  """
  def register_issuer_did(issuer_eoa, pub_key_x, pub_key_y, service_endpoint) do
    method = build_verification_method(pub_key_x, pub_key_y)
    service = build_service_endpoint(service_endpoint)

    DIDRegistryContract.create(issuer_eoa, [method], [service])
    |> Client.send_transaction(to: contract_address())
  end

  @doc """
  Resolve a DID document from on-chain storage.
  """
  def resolve(identity) do
    DIDRegistryContract.resolve(identity)
    |> Client.call(to: contract_address())
  end

  # Build a VerificationMethod tuple for the P-256 assertion key
  defp build_verification_method(pub_key_x, pub_key_y) do
    key_id = ExKeccak.hash_256("key-assert")
    key_type = 0  # P256
    relationships = 2  # bit 1 = assertionMethod

    {key_id, key_type, pad_to_32(pub_key_x), pad_to_32(pub_key_y), relationships}
  end

  # Build a ServiceEndpoint tuple for OID4VCI
  defp build_service_endpoint(endpoint_url) do
    service_id = ExKeccak.hash_256("oid4vci")
    service_type = ExKeccak.hash_256("OpenID4VCIIssuer")

    {service_id, service_type, endpoint_url}
  end

  defp pad_to_32(bin) when byte_size(bin) == 32, do: bin
  defp pad_to_32(bin) when byte_size(bin) < 32 do
    padding = 32 - byte_size(bin)
    <<0::size(padding * 8), bin::binary>>
  end

  defp contract_address do
    Application.get_env(:sovra, :ethereum, [])
    |> Keyword.fetch!(:did_registry_address)
  end
end
