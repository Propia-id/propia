defmodule Sovra.Ethereum.IssuerRegistry do
  @moduledoc """
  Smart contract interaction for SovraIssuerRegistryV1.
  Manages the trusted credential issuer registry.
  """

  alias Sovra.Ethereum.Client
  alias Sovra.Ethereum.Contracts.IssuerRegistryContract

  @doc """
  Register a new issuer with initial credential type hashes.

  - `issuer_address` — 0x-prefixed hex string
  - `credential_type_ids` — list of 32-byte keccak256 hashes of credential type strings
  """
  def register_issuer(issuer_address, credential_type_ids) do
    IssuerRegistryContract.register_issuer(issuer_address, credential_type_ids)
    |> Client.send_transaction(
      to: contract_address(),
      op: :issuer_register,
      subject_id: issuer_address
    )
  end

  @doc """
  Add credential types to an existing issuer.
  """
  def add_credential_types(issuer_address, credential_type_ids) do
    IssuerRegistryContract.add_credential_types(issuer_address, credential_type_ids)
    |> Client.send_transaction(
      to: contract_address(),
      op: :credential_type_register,
      subject_id: issuer_address
    )
  end

  @doc """
  Check if an issuer is trusted for a specific credential type (read-only).
  """
  def is_trusted(issuer_address, credential_type_id) do
    IssuerRegistryContract.is_trusted(issuer_address, credential_type_id)
    |> Client.call(to: contract_address())
  end

  @doc """
  Check if an issuer is registered (read-only).
  """
  def is_registered(issuer_address) do
    IssuerRegistryContract.is_registered(issuer_address)
    |> Client.call(to: contract_address())
  end

  @doc """
  Compute the keccak256 hash of a credential type string for use as a type ID.
  """
  def credential_type_hash(credential_type) when is_binary(credential_type) do
    ExKeccak.hash_256(credential_type)
  end

  defp contract_address do
    Application.get_env(:sovra, :ethereum, [])
    |> Keyword.fetch!(:issuer_registry_address)
  end
end
