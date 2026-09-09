defmodule Sovra.Ethereum.ChainIdProbe.Stub do
  @moduledoc """
  Test `ChainIdProbe` — never touches the network. Configured in
  `config/test.exs`. Resolves an RPC URL against the `:sovra, :stub_chain_ids`
  app env map; URLs not in the map default to `{:ok, @default_chain_id}` so the
  happy path needs no setup.

  Per-test overrides (set with `Application.put_env/3`, reset in `on_exit`):

      Application.put_env(:sovra, :stub_chain_ids, %{
        "https://unreachable.test" => {:error, :chain_id_unreachable}
      })

  A zero-arity function is called instead of returned, so a test can make a
  probe slow or make it raise:

      %{"https://slow.test" => fn -> Process.sleep(200) && {:ok, 1337} end}
  """
  @behaviour Sovra.Ethereum.ChainIdProbe

  # Matches config/test.exs `:ethereum` chain_id, so an unlisted URL reads as
  # the configured chain rather than as a mismatch.
  @default_chain_id 65_536_999

  @impl true
  def chain_id(rpc_url) when is_binary(rpc_url) do
    :sovra
    |> Application.get_env(:stub_chain_ids, %{})
    |> Map.get(rpc_url, {:ok, @default_chain_id})
    |> resolve()
  end

  defp resolve(fun) when is_function(fun, 0), do: fun.()
  defp resolve(result), do: result
end
