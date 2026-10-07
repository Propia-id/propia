defmodule SovraTest.Ethereum.StubSignatureRegistry do
  @moduledoc """
  Test stub for `Sovra.Ethereum.SignatureRegistry`. Wired in via the
  `:signature_registry` config in `config/test.exs` so documents can be
  issued and anchored end-to-end without a live chain.

  Returns a deterministic fake transaction hash. Tests that need the
  anchoring or the unconfigured path should swap this module via
  `Application.put_env(:sovra, :signature_registry, ...)` for the
  duration of the test.
  """

  def record(_signer, _type_id, _digest, _r, _s), do: {:ok, "0xstubtxhash"}
  def find_record(_signer, _digest), do: {:error, :record_not_found}
  def configured?, do: true
end

defmodule SovraTest.Ethereum.AlreadyRecordedSignatureRegistry do
  @moduledoc """
  Test variant for a signature that is already on-chain: an earlier anchoring
  transaction landed after its receipt poll gave up. Mirrors what
  `Sovra.Ethereum.SignatureRegistry` returns when `record` reverts with
  `AlreadyRecorded()`, and finds that earlier transaction.
  """

  def record(_signer, _type_id, _digest, _r, _s), do: {:ok, :already_recorded}

  def find_record(_signer, _digest),
    do: {:ok, %{tx_hash: "0xearliertxhash", recorded_at: ~U[2026-09-30 12:00:00Z]}}

  def configured?, do: true
end

defmodule SovraTest.Ethereum.AlwaysFailingSignatureRegistry do
  @moduledoc """
  Test variant whose anchoring transaction never lands, so anchoring ends
  `failed` with the document already signed and stored.
  """

  def record(_signer, _type_id, _digest, _r, _s), do: {:error, :transaction_reverted}
  def find_record(_signer, _digest), do: {:error, :record_not_found}
  def configured?, do: true
end

defmodule SovraTest.Ethereum.UnconfiguredSignatureRegistry do
  @moduledoc """
  Test variant standing in for a deployment with no signature registry, where
  issuance refuses to sign rather than hand out a document nothing can anchor.
  """

  def record(_signer, _type_id, _digest, _r, _s), do: {:error, :chain_not_configured}
  def find_record(_signer, _digest), do: {:error, :chain_not_configured}
  def configured?, do: false
end
