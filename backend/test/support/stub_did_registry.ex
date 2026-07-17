defmodule SovraTest.Ethereum.StubDIDRegistry do
  @moduledoc """
  Test stub for `Sovra.Ethereum.DIDRegistry`. Wired in via the
  `:did_registry` config in `config/test.exs` so the workspace
  provisioning job can run end-to-end without a live chain.

  Returns a deterministic fake transaction hash. Tests that need to
  exercise chain failures should swap this module via
  `Application.put_env(:sovra, :did_registry, ...)` for the duration of
  the test.
  """

  def register_issuer_did(_eoa, _x, _y, _service_endpoint), do: {:ok, "0xstubtxhash"}
end

defmodule SovraTest.Ethereum.AlwaysFailingDIDRegistry do
  @moduledoc """
  Test variant that always reports a transient chain failure. Used to
  drive the provisioning job's retry/discard paths.
  """

  def register_issuer_did(_eoa, _x, _y, _service_endpoint), do: {:error, :rpc_down}
end

defmodule SovraTest.Ethereum.AlreadyRegisteredDIDRegistry do
  @moduledoc """
  Test variant simulating an identity whose DID is already on-chain. Mirrors
  what `Sovra.Ethereum.DIDRegistry` returns when `create` reverts with
  `DIDAlreadyExists()`, so the provisioning job can be exercised against the
  idempotent-success path.
  """

  def register_issuer_did(_eoa, _x, _y, _service_endpoint), do: {:ok, :already_registered}
end
