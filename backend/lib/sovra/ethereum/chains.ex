defmodule Sovra.Ethereum.Chains do
  @moduledoc """
  The chain inventory that relayer monitoring reads.

  Sovra runs a single chain (`config :sovra, :ethereum`, from `CHAIN_ID` /
  `L2_RPC_URL`), so this is a one-entry registry. It is shaped as a registry
  anyway because the exported metrics, the alert rules and the dashboard are all
  keyed by `chain_id`: a second chain later needs no change to any of them.

  `name/1` falls back to `chain-<id>` so every series always carries a
  `chain_name` — the Prometheus reporter drops a sample whose declared tag is
  missing from the event metadata, silently, and that label is what lets an
  alert notification say which network drained.
  """

  alias Sovra.Ethereum.Client

  @type chain :: %{chain_id: pos_integer(), name: String.t(), rpc_url: String.t() | nil}

  @doc "Every known chain, keyed by chain id."
  @spec all() :: %{pos_integer() => chain()}
  def all do
    case chain() do
      %{chain_id: id} = chain -> %{id => chain}
      nil -> %{}
    end
  end

  @doc "The chain with this id, or `:unknown_chain` when it is not the configured one."
  @spec get(pos_integer()) :: {:ok, chain()} | {:error, :unknown_chain}
  def get(chain_id) do
    case chain() do
      %{chain_id: ^chain_id} = chain -> {:ok, chain}
      _ -> {:error, :unknown_chain}
    end
  end

  @doc """
  Whether on-chain writes are configured for `chain_id` — sovra's analogue of
  "the registry contracts are deployed here".

  `Sovra.Ethereum.Client.configured?/0` is the single source of truth, so this
  cannot disagree with what the submit path will actually attempt. A chain that
  is polled but not configured is reported as such rather than omitted: an alert
  rule otherwise cannot tell "not monitored" from "healthy".
  """
  @spec configured?(pos_integer()) :: boolean()
  def configured?(chain_id) do
    match?({:ok, _}, get(chain_id)) and Client.configured?()
  end

  defp chain do
    config = Application.get_env(:sovra, :ethereum, [])

    case Keyword.get(config, :chain_id) do
      id when is_integer(id) and id > 0 ->
        %{chain_id: id, name: name(config, id), rpc_url: Keyword.get(config, :rpc_url)}

      _ ->
        nil
    end
  end

  defp name(config, id) do
    case Keyword.get(config, :chain_name) do
      name when is_binary(name) and name != "" -> name
      _ -> "chain-#{id}"
    end
  end
end
