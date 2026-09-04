defmodule Sovra.Ethereum.Client do
  @moduledoc """
  Thin wrapper for sending signed Ethereum transactions and making read-only calls
  using the admin private key configured via environment.
  """

  @behaviour Sovra.Ethereum.BalanceReader

  use Sovra.Log

  alias Sovra.Ethereum.Chains

  # Receipt polling window. Defaults cover a public testnet (Sepolia blocks
  # are ~12s, and a tx may take a few blocks to confirm): 45 polls × 2s ≈ 90s.
  # Fast chains (local devnet) return on the first poll, so the wider window
  # costs nothing on the happy path. Both are overridable via the :ethereum
  # config (`:receipt_poll_attempts`, `:receipt_poll_interval_ms`).
  @default_receipt_poll_attempts 45
  @default_receipt_poll_interval_ms 2_000

  @doc """
  Sends a signed transaction and waits for its receipt.

  Options:

    * `:to` — the contract address.
    * `:op` — what this transaction *is* (`:did_register`, `:revoke`, …). Every
      caller passes one, and every log line and alert facet is keyed on it: a
      failing transaction used to be a bare `"Transaction failed: …"` with no
      way to tell a DID registration from a revocation sync from a document
      anchoring.
    * `:subject_id` — the thing the operation acts on (a workspace id, a
      credential id, a document id), so a chain failure joins the business
      event that caused it.
    * `:workspace_id` — the tenant, when the caller knows it.
  """
  def send_transaction(tx_data, opts \\ []) do
    config = ethereum_config()
    context = Keyword.take(opts, [:op, :subject_id, :workspace_id])

    with {:ok, {signer, signer_opts}} <- relayer_signer(),
         {:ok, [from_address]} <- signer.accounts(signer_opts) do
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
      |> handle_send_result(context)
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

  @doc """
  The configured `Ethers.Signer` for the relayer, as `{module, opts}`.

  Local (in-process `ADMIN_PRIVATE_KEY`) for dev/test/local; the KMS signer
  service (no key material on this node) in production. Public because
  `Sovra.Ethereum.Relayer` resolves the relayer's address through the same
  signer the submit path signs with — the two must not be able to disagree.

  `Keyword.get`, not `fetch!`: an unconfigured local relayer must surface as
  `Ethers.Signer.Local`'s `{:error, :no_private_key}` rather than raising, so
  read-only callers (monitoring) can report it instead of crashing.
  """
  @spec relayer_signer() :: {:ok, {module(), keyword()}} | {:error, term()}
  def relayer_signer do
    config = ethereum_config()

    case Keyword.get(config, :relayer_backend, :local) do
      :kms -> {:ok, {Sovra.Ethereum.KmsSigner, []}}
      _ -> {:ok, {Ethers.Signer.Local, [private_key: Keyword.get(config, :admin_private_key)]}}
    end
  end

  @doc """
  Native-token balance of `address` at the latest block, in wei.

  Resolved through `Sovra.Ethereum.Chains`, not `configured?/0`: the relayer
  holds a balance on the chain whether or not the registry contracts are set.
  """
  @impl true
  @spec get_balance(pos_integer(), <<_::160>>) :: {:ok, non_neg_integer()} | {:error, term()}
  def get_balance(chain_id, <<_::binary-size(20)>> = address) do
    with {:ok, url} <- rpc_url_for(chain_id),
         {:ok, hex} <-
           Ethereumex.HttpClient.eth_get_balance(hex0x(address), "latest", url: url) do
      decode_uint(hex)
    end
  end

  # `:unknown_chain` means not the configured chain; `:chain_rpc_not_configured`
  # means configured without an RPC URL. The monitor labels them the same way,
  # but the log line has to be able to tell them apart.
  defp rpc_url_for(chain_id) do
    case Chains.get(chain_id) do
      {:ok, %{rpc_url: url}} when is_binary(url) and url != "" -> {:ok, url}
      {:ok, %{}} -> {:error, :chain_rpc_not_configured}
      {:error, _} = err -> err
    end
  end

  defp hex0x(bin), do: "0x" <> Base.encode16(bin, case: :lower)

  # Strict on purpose: a malformed response must not read as a legitimate zero,
  # or a drained relayer and a broken RPC endpoint become indistinguishable.
  defp decode_uint("0x"), do: {:ok, 0}

  defp decode_uint("0x" <> hex) when hex != "" do
    case Integer.parse(hex, 16) do
      {n, ""} when n >= 0 -> {:ok, n}
      _ -> {:error, :invalid_uint_response}
    end
  end

  defp decode_uint(_), do: {:error, :invalid_uint_response}

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

  defp handle_send_result({:ok, tx_hash}, context) do
    Log.event(:info, "chain transaction submitted", [
      {:event, "chain.tx.submitted"},
      {:tx_hash, tx_hash} | context
    ])

    config = ethereum_config()
    started = System.monotonic_time(:millisecond)

    await_receipt(
      tx_hash,
      Keyword.get(config, :receipt_poll_attempts, @default_receipt_poll_attempts),
      Keyword.get(config, :receipt_poll_interval_ms, @default_receipt_poll_interval_ms),
      context,
      started
    )
  end

  defp handle_send_result({:error, reason} = error, context) do
    Log.event(:error, "chain transaction send failed", [
      {:event, "chain.tx.send_failed"},
      {:reason, Log.reason(reason)} | context
    ])

    error
  end

  defp await_receipt(tx_hash, attempts, interval_ms, context, started) do
    config = ethereum_config()

    case Ethers.get_transaction_receipt(tx_hash, rpc_opts: rpc_opts(config)) do
      {:ok, %{"status" => "0x1"} = receipt} ->
        Log.event(:info, "chain transaction confirmed", [
          {:event, "chain.tx.confirmed"},
          {:tx_hash, tx_hash},
          {:block_number, block_number(receipt)},
          {:confirm_ms, System.monotonic_time(:millisecond) - started} | context
        ])

        {:ok, tx_hash}

      {:ok, %{"status" => "0x0"}} ->
        Log.event(:error, "chain transaction reverted", [
          {:event, "chain.tx.reverted"},
          {:tx_hash, tx_hash},
          {:confirm_ms, System.monotonic_time(:millisecond) - started} | context
        ])

        {:error, :transaction_reverted}

      {:error, :transaction_receipt_not_found} when attempts > 0 ->
        Process.sleep(interval_ms)
        await_receipt(tx_hash, attempts - 1, interval_ms, context, started)

      {:error, :transaction_receipt_not_found} ->
        # The transaction may still land later, so the DB and the chain are now
        # possibly out of step — the tx_hash is what reconciles them by hand.
        Log.event(:error, "chain transaction receipt not found", [
          {:event, "chain.tx.receipt_timeout"},
          {:tx_hash, tx_hash},
          {:waited_ms, System.monotonic_time(:millisecond) - started} | context
        ])

        {:error, :receipt_timeout}

      other ->
        Log.event(:error, "unexpected chain receipt", [
          {:event, "chain.tx.receipt_unexpected"},
          {:tx_hash, tx_hash},
          {:reason, Log.reason(other)} | context
        ])

        {:error, :unexpected_receipt}
    end
  end

  defp block_number(%{"blockNumber" => "0x" <> hex}), do: String.to_integer(hex, 16)
  defp block_number(%{"blockNumber" => n}) when is_integer(n), do: n
  defp block_number(_), do: nil

  defp ethereum_config do
    Application.get_env(:sovra, :ethereum, [])
  end

  defp rpc_opts(config) do
    [url: Keyword.get(config, :rpc_url, "http://127.0.0.1:1729")]
  end
end
