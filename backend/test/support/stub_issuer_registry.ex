defmodule SovraTest.Ethereum.StubIssuerRegistry do
  @moduledoc """
  Test stub for `Sovra.Ethereum.IssuerRegistry`. Wired in via the
  `:issuer_registry` config in `config/test.exs` so workspace provisioning and
  credential type registration can run end-to-end without a live chain.

  Writes report themselves to the calling process, so a test can assert which
  ones ran. Every type reads as untrusted, so registration always writes.
  Tests that need a failure or an already-registered issuer swap in one of the
  variants below via `Application.put_env(:sovra, :issuer_registry, ...)`.
  """

  def register_issuer(issuer, type_ids) do
    send(self(), {:issuer_registry, :register_issuer, issuer, type_ids})
    {:ok, "0xstubtxhash"}
  end

  def add_credential_types(issuer, type_ids) do
    send(self(), {:issuer_registry, :add_credential_types, issuer, type_ids})
    {:ok, "0xstubtxhash"}
  end

  def is_trusted(_issuer, _type_id), do: {:ok, false}
end

defmodule SovraTest.Ethereum.AlreadyRegisteredIssuerRegistry do
  @moduledoc """
  Test variant for an issuer that is already on-chain and already trusted for
  every type. Mirrors what `Sovra.Ethereum.IssuerRegistry` returns when
  `registerIssuer` reverts with `AlreadyRegistered()`.
  """

  def register_issuer(_issuer, _type_ids), do: {:ok, :already_registered}

  def add_credential_types(issuer, type_ids) do
    send(self(), {:issuer_registry, :add_credential_types, issuer, type_ids})
    {:ok, "0xstubtxhash"}
  end

  def is_trusted(_issuer, _type_id), do: {:ok, true}
end

defmodule SovraTest.Ethereum.AlwaysFailingIssuerRegistry do
  @moduledoc """
  Test variant that always reports a transient chain failure, for the retry
  and final-failure paths.
  """

  def register_issuer(_issuer, _type_ids), do: {:error, :rpc_down}
  def add_credential_types(_issuer, _type_ids), do: {:error, :rpc_down}
  def is_trusted(_issuer, _type_id), do: {:error, :rpc_down}
end
