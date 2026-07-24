defmodule Sovra.Ethereum.Client do
  @moduledoc """
  Thin wrapper for sending signed Ethereum transactions and making read-only calls
  using the admin private key configured via environment.
  """

  require Logger

  # Receipt polling window. Defaults cover a public testnet (Sepolia blocks
  # are ~12s, and a tx may take a few blocks to confirm): 45 polls × 2s ≈ 90s.
  # Fast chains (local devnet) return on the first poll, so the wider window
  # costs nothing on the happy path. Both are overridable via the :ethereum
  # config (`:receipt_poll_attempts`, `:receipt_poll_interval_ms`).
  @default_receipt_poll_attempts 45
  @default_receipt_poll_interval_ms 2_000

  def send_transaction(tx_data, opts \\ []) do
    config = ethereum_config()
    {signer, signer_opts} = relayer_signer(config)

    with {:ok, [from_address]} <- signer.accounts(signer_opts) do
      send_opts =
        [
          to: opts[:to],
          from: from_address,
          signer: signer,
          signer_opts: signer_opts,
          rpc_opts: rpc_opts(config)
        ]
        |> Keyword.filter(fn {_k, v} -> v != nil end)

      tx_data
      |> Ethers.send_transaction(send_opts)
      |> handle_send_result()
    end
  end

  @doc """
  Whether on-chain operations are configured: a relayer signer (local admin key
  or the KMS signer) plus a DID registry address.
  """
  def configured? do
    config = ethereum_config()

    has_relayer =
      Keyword.get(config, :relayer_backend) == :kms or
        Keyword.get(config, :admin_private_key) not in [nil, ""]

    has_relayer and Keyword.get(config, :did_registry_address) not in [nil, ""]
  end

  # Local (in-process ADMIN_PRIVATE_KEY) for dev/test/local; KMS signer service
  # (no key material on this node) in production.
  defp relayer_signer(config) do
    case Keyword.get(config, :relayer_backend, :local) do
      :kms -> {Sovra.Ethereum.KmsSigner, []}
      _ -> {Ethers.Signer.Local, [private_key: Keyword.fetch!(config, :admin_private_key)]}
    end
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
    config = ethereum_config()

    await_receipt(
      tx_hash,
      Keyword.get(config, :receipt_poll_attempts, @default_receipt_poll_attempts),
      Keyword.get(config, :receipt_poll_interval_ms, @default_receipt_poll_interval_ms)
    )
  end

  defp handle_send_result({:error, reason} = error) do
    Logger.error("Transaction failed: #{inspect(reason)}")
    error
  end

  defp await_receipt(tx_hash, attempts, interval_ms) do
    config = ethereum_config()

    case Ethers.get_transaction_receipt(tx_hash, rpc_opts: rpc_opts(config)) do
      {:ok, %{"status" => "0x1"}} ->
        {:ok, tx_hash}

      {:ok, %{"status" => "0x0"}} ->
        Logger.error("Transaction reverted: #{tx_hash}")
        {:error, :transaction_reverted}

      {:error, :transaction_receipt_not_found} when attempts > 0 ->
        Process.sleep(interval_ms)
        await_receipt(tx_hash, attempts - 1, interval_ms)

      {:error, :transaction_receipt_not_found} ->
        Logger.error("Transaction receipt not found after retries: #{tx_hash}")
        {:error, :receipt_timeout}

      other ->
        Logger.error("Unexpected receipt result: #{inspect(other)}")
        {:error, :unexpected_receipt}
    end
  end

  defp ethereum_config do
    Application.get_env(:sovra, :ethereum, [])
  end

  defp rpc_opts(config) do
    [url: Keyword.get(config, :rpc_url, "http://127.0.0.1:1729")]
  end
end
