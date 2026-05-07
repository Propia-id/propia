defmodule SovraTest.Ethereum.StubRevocationRegistry do
  @moduledoc """
  Test stub for `Sovra.Ethereum.RevocationRegistry`. Wired in via the
  `:revocation_registry` config in `config/test.exs` so issuer-side
  status changes (revoke/suspend/unsuspend) and bitmap initialization
  can run end-to-end without a live chain.

  Returns deterministic fake transaction hashes. Tests that need to
  exercise chain failures should swap this module via
  `Application.put_env(:sovra, :revocation_registry, ...)` for the
  duration of the test.
  """

  def initialize_bitmap(_issuer_address, _purpose), do: {:ok, "0xstubtxhash"}
  def revoke(_issuer_address, _index), do: {:ok, "0xstubtxhash"}
  def suspend(_issuer_address, _index), do: {:ok, "0xstubtxhash"}
  def unsuspend(_issuer_address, _index), do: {:ok, "0xstubtxhash"}
end
