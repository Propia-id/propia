defmodule Sovra.Ethereum.Client do
  @moduledoc """
  Thin wrapper for sending signed Ethereum transactions and making read-only calls
  using the admin private key configured via environment.
  """

  require Logger

  def send_transaction(tx_data, opts \\ []) do
    config = ethereum_config()
    private_key = Keyword.fetch!(config, :admin_private_key)

    {:ok, [from_address]} = Ethers.Signer.Local.accounts(private_key: private_key)

    send_opts =
      [
        to: opts[:to],
        from: from_address,
        signer: Ethers.Signer.Local,
        signer_opts: [private_key: private_key],
        rpc_opts: rpc_opts(config)
      ]
      |> Keyword.filter(fn {_k, v} -> v != nil end)

    tx_data
    |> Ethers.send_transaction(send_opts)
    |> handle_send_result()
  end

  def call(tx_data, opts \\ []) do
    config = ethereum_config()

    call_opts =
      [
        to: opts[:to],
        rpc_opts: rpc_opts(config)
      ]
      |> Keyword.filter(fn {_k, v} -> v != nil end)

    Ethers.call(tx_data, call_opts)
  end

  defp handle_send_result({:ok, tx_hash}) do
    Logger.info("Transaction sent: #{tx_hash}")
    {:ok, tx_hash}
  end

  defp handle_send_result({:error, reason} = error) do
    Logger.error("Transaction failed: #{inspect(reason)}")
    error
  end

  defp ethereum_config do
    Application.get_env(:sovra, :ethereum, [])
  end

  defp rpc_opts(config) do
    [url: Keyword.get(config, :rpc_url, "http://127.0.0.1:1729")]
  end
end
