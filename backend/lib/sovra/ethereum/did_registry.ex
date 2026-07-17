defmodule Sovra.Ethereum.DIDRegistry do
  @moduledoc """
  Smart contract interaction for SovraDIDRegistry.
  Manages on-chain DID documents for issuers and verifiers.
  """

  alias Sovra.Ethereum.Client
  alias Sovra.Ethereum.Contracts.DIDRegistryContract
  alias Sovra.Crypto.P256

  # Selector for the DIDAlreadyExists() custom error, derived from its
  # signature at compile time: keccak256("DIDAlreadyExists()")[0..3] = 0x338c38da.
  @did_already_exists_selector "0x" <>
                                 ("DIDAlreadyExists()"
                                  |> ExKeccak.hash_256()
                                  |> binary_part(0, 4)
                                  |> Base.encode16(case: :lower))

  @doc """
  Register an issuer DID on-chain with their P-256 signing key and OID4VCI service endpoint.

  - `issuer_eoa` — the identity address (0x-prefixed hex string)
  - `pub_key_x`, `pub_key_y` — 32-byte binaries of the P-256 public key
  - `service_endpoint` — OID4VCI base URL string

  A `create` that reverts with `DIDAlreadyExists()` is treated as success
  (`{:ok, :already_registered}`): the identity is already on-chain, which is
  the exact end state provisioning wants. This makes the call idempotent so a
  retry after a mined-but-unrecorded transaction (e.g. the receipt poll timed
  out) converges instead of wedging the workspace in a failed state.
  """
  def register_issuer_did(issuer_eoa, pub_key_x, pub_key_y, service_endpoint) do
    method = build_verification_method(pub_key_x, pub_key_y)
    service = build_service_endpoint(service_endpoint)

    DIDRegistryContract.create(issuer_eoa, [method], [service])
    |> Client.send_transaction(to: contract_address())
    |> handle_registration_result()
  end

  defp handle_registration_result({:error, reason}) do
    if did_already_exists?(reason), do: {:ok, :already_registered}, else: {:error, reason}
  end

  defp handle_registration_result(result), do: result

  @doc """
  Detects the `DIDAlreadyExists()` revert selector in a JSON-RPC error returned
  by a reverted `create` call. Pure; exposed for testing.
  """
  def did_already_exists?(reason) when is_map(reason) do
    [Map.get(reason, "data"), Map.get(reason, "message")]
    |> Enum.filter(&is_binary/1)
    |> Enum.any?(&String.contains?(&1, @did_already_exists_selector))
  end

  def did_already_exists?(reason) when is_binary(reason),
    do: String.contains?(reason, @did_already_exists_selector)

  def did_already_exists?(_reason), do: false

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
    # P256
    key_type = 0
    # bit 1 = assertionMethod
    relationships = 2

    {key_id, key_type, P256.pad_or_trim(pub_key_x, 32), P256.pad_or_trim(pub_key_y, 32),
     relationships}
  end

  # Build a ServiceEndpoint tuple for OID4VCI
  defp build_service_endpoint(endpoint_url) do
    service_id = ExKeccak.hash_256("oid4vci")
    service_type = ExKeccak.hash_256("OpenID4VCIIssuer")

    {service_id, service_type, endpoint_url}
  end

  defp contract_address do
    Application.get_env(:sovra, :ethereum, [])
    |> Keyword.fetch!(:did_registry_address)
  end
end
