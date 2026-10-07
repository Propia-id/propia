defmodule Sovra.Ethereum.SignatureRegistry do
  @moduledoc """
  Smart contract interaction for SignatureRegistryV1.

  Stores the issuer's P-256 signature over a signed document, keyed by
  `(signer, digest)`. The contract verifies the signature against the signer's
  registered key before storing it, so a stored record means the chain checked
  it — not merely that someone submitted it.

  The document payload never goes on-chain: only 32 bytes of digest and 64 of
  signature, which reveal nothing about the content.
  """

  alias Sovra.Ethereum.Client
  alias Sovra.Ethereum.Contracts.SignatureRegistryContract
  alias Sovra.Ethereum.Revert

  @already_recorded_selector Revert.selector("AlreadyRecorded()")

  @doc """
  Verify and store a signature.

  - `signer_address` — 0x-prefixed hex string (the workspace EOA)
  - `type_id` — 32 bytes, `keccak256(credential_type)`
  - `digest` — 32 bytes, `sha256` of the JWS signing input
  - `r`, `s` — 32 bytes each, the P-256 signature components (low-s)

  A revert with `AlreadyRecorded()` is `{:ok, :already_recorded}`: the record
  exists, which is the end state the caller wants, but this call sent nothing,
  so the transaction that wrote it has to come from `find_record/2`.
  """
  def record(signer_address, type_id, digest, r, s) do
    SignatureRegistryContract.record(signer_address, type_id, digest, r, s)
    |> Client.send_transaction(
      to: contract_address(),
      op: :document_anchor,
      subject_id: Base.encode16(digest, case: :lower)
    )
    |> case do
      {:error, reason} = error ->
        if Revert.matches?(reason, @already_recorded_selector),
          do: {:ok, :already_recorded},
          else: error

      result ->
        result
    end
  end

  @doc """
  The transaction that recorded `(signer, digest)`, and when, found through its
  `SignatureRecorded` event. For a record whose transaction hash was lost: one
  that landed after its receipt poll gave up. Both are indexed topics, so this
  is one `eth_getLogs` over the whole chain.
  """
  def find_record(signer_address, digest) do
    SignatureRegistryContract.EventFilters.signature_recorded(signer_address, digest)
    |> Client.get_logs(address: contract_address(), fromBlock: "earliest")
    |> case do
      {:ok, [%Ethers.Event{transaction_hash: tx_hash, data: [recorded_at]} | _]} ->
        {:ok, %{tx_hash: tx_hash, recorded_at: DateTime.from_unix!(recorded_at)}}

      {:ok, []} ->
        {:error, :record_not_found}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Read a stored record (read-only). Absent records come back with
  `recorded_at == 0`.
  """
  def get_record(signer_address, digest) do
    SignatureRegistryContract.get_record(signer_address, digest)
    |> Client.call(to: contract_address())
  end

  @doc """
  Whether a record exists for this `(signer, digest)` pair (read-only).
  """
  def is_recorded(signer_address, digest) do
    SignatureRegistryContract.is_recorded(signer_address, digest)
    |> Client.call(to: contract_address())
  end

  @doc """
  Whether on-chain recording is configured. Issuance refuses to sign without it,
  rather than handing out a document that can never be anchored.
  """
  def configured? do
    Client.configured?() and contract_address() not in [nil, ""]
  end

  defp contract_address do
    Application.get_env(:sovra, :ethereum, [])
    |> Keyword.get(:signature_registry_address)
  end
end
