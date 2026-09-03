defmodule Sovra.Ethereum.RevocationRegistry do
  @moduledoc """
  Smart contract interaction for SovraRevocationRegistryV1.
  Manages per-issuer credential status bitmaps (revocation and suspension).
  """

  alias Sovra.Ethereum.Client
  alias Sovra.Ethereum.Contracts.RevocationRegistryContract

  @revocation 0
  @suspension 1

  @doc """
  Initialize a bitmap for an issuer and purpose.
  Must be called once per (issuer, purpose) pair before any status changes.

  - `issuer_address` — 0x-prefixed hex string
  - `purpose` — 0 (revocation) or 1 (suspension)
  """
  def initialize_bitmap(issuer_address, purpose \\ @revocation) do
    RevocationRegistryContract.initialize_bitmap(issuer_address, purpose)
    |> Client.send_transaction(
      to: contract_address(),
      op: :bitmap_initialize,
      subject_id: issuer_address
    )
  end

  @doc """
  Revoke a credential (set bit to 1, permanent).
  """
  def revoke(issuer_address, index) do
    RevocationRegistryContract.set_status(issuer_address, @revocation, index)
    |> Client.send_transaction(
      to: contract_address(),
      op: :credential_revoke,
      subject_id: index
    )
  end

  @doc """
  Suspend a credential (set bit to 1, reversible).
  """
  def suspend(issuer_address, index) do
    RevocationRegistryContract.set_status(issuer_address, @suspension, index)
    |> Client.send_transaction(
      to: contract_address(),
      op: :credential_suspend,
      subject_id: index
    )
  end

  @doc """
  Un-suspend a credential (clear bit to 0).
  """
  def unsuspend(issuer_address, index) do
    RevocationRegistryContract.clear_status(issuer_address, @suspension, index)
    |> Client.send_transaction(
      to: contract_address(),
      op: :credential_unsuspend,
      subject_id: index
    )
  end

  @doc """
  Revoke multiple credentials in a single transaction.
  """
  def batch_revoke(issuer_address, indices) do
    RevocationRegistryContract.batch_set_status(issuer_address, @revocation, indices)
    |> Client.send_transaction(
      to: contract_address(),
      op: :credential_batch_revoke,
      subject_id: issuer_address
    )
  end

  @doc """
  Check if a credential is revoked (read-only).
  """
  def is_revoked(issuer_address, index) do
    RevocationRegistryContract.get_status(issuer_address, @revocation, index)
    |> Client.call(to: contract_address())
  end

  @doc """
  Check if a credential is suspended (read-only).
  """
  def is_suspended(issuer_address, index) do
    RevocationRegistryContract.get_status(issuer_address, @suspension, index)
    |> Client.call(to: contract_address())
  end

  @doc """
  Fetch the full bitmap for an issuer and purpose (read-only).
  Returns a list of uint256 values (at least 512 entries).
  """
  def get_bitmap(issuer_address, purpose \\ @revocation) do
    RevocationRegistryContract.get_bitmap(issuer_address, purpose)
    |> Client.call(to: contract_address())
  end

  defp contract_address do
    Application.get_env(:sovra, :ethereum, [])
    |> Keyword.fetch!(:revocation_registry_address)
  end
end
