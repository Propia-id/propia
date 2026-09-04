defmodule Sovra.Ethereum.BalanceReader.Stub do
  @moduledoc """
  Test `BalanceReader` — never touches the network. Configured in
  `config/test.exs`. Resolves a chain id against the
  `:sovra, :stub_balances` app env map; ids not in the map default to
  `{:ok, @default_wei}` so the happy path needs no setup.

  Per-test overrides (set with `Application.put_env/3`, reset in `on_exit`):

      Application.put_env(:sovra, :stub_balances, %{
        65_536_101 => {:ok, 1_500_000_000_000_000_000},
        1 => {:error, :econnrefused},
        # blocks long enough to trip the monitor's per-chain timeout
        999 => {:sleep, 5_000}
      })
  """
  @behaviour Sovra.Ethereum.BalanceReader

  @default_wei 1_000_000_000_000_000_000

  def default_wei, do: @default_wei

  @impl true
  def get_balance(chain_id, <<_::binary-size(20)>>) when is_integer(chain_id) do
    :sovra
    |> Application.get_env(:stub_balances, %{})
    |> Map.get(chain_id, {:ok, @default_wei})
    |> case do
      {:sleep, ms} ->
        Process.sleep(ms)
        {:ok, @default_wei}

      {:raise, message} ->
        raise message

      result ->
        result
    end
  end
end
