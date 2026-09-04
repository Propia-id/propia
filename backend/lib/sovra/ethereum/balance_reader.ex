defmodule Sovra.Ethereum.BalanceReader do
  @moduledoc """
  The single RPC read `Sovra.Ethereum.Relayer.BalanceMonitor` needs, expressed
  as a behaviour so the test suite never dials a real endpoint.

      config :sovra, :relayer_balance_reader,
        Sovra.Ethereum.BalanceReader.Stub

  Defaults to `Sovra.Ethereum.Client`.
  """

  @callback get_balance(chain_id :: pos_integer(), address :: <<_::160>>) ::
              {:ok, non_neg_integer()} | {:error, term()}

  @doc "The configured implementation."
  @spec impl() :: module()
  def impl, do: Application.get_env(:sovra, :relayer_balance_reader, Sovra.Ethereum.Client)
end
