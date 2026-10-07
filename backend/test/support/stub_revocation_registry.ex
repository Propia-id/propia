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

  def initialize_bitmap(issuer_address, purpose) do
    send(self(), {:revocation_registry, :initialize_bitmap, issuer_address, purpose})
    {:ok, "0xstubtxhash"}
  end

  def revoke(_issuer_address, _index), do: {:ok, "0xstubtxhash"}
  def suspend(_issuer_address, _index), do: {:ok, "0xstubtxhash"}
  def unsuspend(_issuer_address, _index), do: {:ok, "0xstubtxhash"}
end

defmodule SovraTest.Ethereum.FailingBitmapRevocationRegistry do
  @moduledoc """
  Test variant whose bitmap initialization always fails, for a provisioning
  run that registers the issuer and then stops.
  """

  def initialize_bitmap(_issuer_address, _purpose), do: {:error, :rpc_down}
end

defmodule SovraTest.Ethereum.AlwaysFailingRevocationRegistry do
  @moduledoc """
  Test variant whose status-list writes always fail, for a credential status
  change that never lands.
  """

  def initialize_bitmap(_issuer_address, _purpose), do: {:error, :rpc_down}
  def revoke(_issuer_address, _index), do: {:error, :rpc_down}
  def suspend(_issuer_address, _index), do: {:error, :rpc_down}
  def unsuspend(_issuer_address, _index), do: {:error, :rpc_down}
end
