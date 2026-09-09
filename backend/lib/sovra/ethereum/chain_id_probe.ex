defmodule Sovra.Ethereum.ChainIdProbe do
  @moduledoc """
  The single RPC read `Sovra.Health` needs, expressed as a behaviour so the test
  suite never dials a real endpoint.

      config :sovra, :chain_id_probe, Sovra.Ethereum.ChainIdProbe.Stub

  Defaults to `Sovra.Ethereum.Client`, which is also the module the submit path
  uses, so the readiness check and the writes it predicts cannot disagree about
  what "the RPC endpoint" means.

  `eth_chainId` rather than a bare TCP connect: it is reachability and
  correctness in one call, and an endpoint answering for the wrong chain is
  worse than one that does not answer at all.
  """

  @callback chain_id(rpc_url :: String.t()) :: {:ok, pos_integer()} | {:error, term()}

  @doc "The configured implementation."
  @spec impl() :: module()
  def impl, do: Application.get_env(:sovra, :chain_id_probe, Sovra.Ethereum.Client)

  @doc "Reads the chain id `rpc_url` reports."
  @spec fetch(String.t()) :: {:ok, pos_integer()} | {:error, term()}
  def fetch(rpc_url), do: impl().chain_id(rpc_url)
end
