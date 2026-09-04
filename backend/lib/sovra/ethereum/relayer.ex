defmodule Sovra.Ethereum.Relayer do
  @moduledoc """
  The relayer's address, for everything that needs to know it without signing.

  One relayer key pays gas for every on-chain write. In production it lives in
  AWS KMS and only the signer box can reach it, so the address is an HTTP
  round-trip away (`GET /v1/relayer/address`, via `Sovra.Ethereum.KmsSigner`);
  in dev/test it is derived in-process from `ADMIN_PRIVATE_KEY`. Either way it
  resolves through the same `Ethers.Signer` the submit path signs with
  (`Sovra.Ethereum.Client.relayer_signer/0`), so the two cannot disagree.

  Its balance is polled per chain by `Sovra.Ethereum.Relayer.BalanceMonitor`
  and exported to Prometheus; nothing here gates on it.
  """

  alias Sovra.Ethereum.Client

  require Logger

  # Memo for `cached_address/0`. The TTL bounds how long monitoring can watch a
  # superseded address: rotating the relayer key changes `relayer_kms_key_id` on
  # the SIGNER, which `signer.deploy` restarts without restarting the API nodes,
  # so nothing here would otherwise notice. Overridable only so tests can force
  # an expiry — changing it for real needs a deploy, which clears the memo anyway.
  @address_key {__MODULE__, :address}
  @address_ttl_ms :timer.hours(24)

  @doc """
  The relayer's address as 20 raw bytes, derived through the configured Signer.

  Under the KMS backend this calls the signer every time — the API node holds no
  key cache. The submit path (`Sovra.Ethereum.Client.send_transaction/2`) uses
  the signer directly for the same reason: a stale address there would build a
  transaction whose `from` no longer matches the signing key, so the nonce and
  the signature would both be wrong. Read-only callers should prefer
  `cached_address/0`.
  """
  @spec address() :: {:ok, <<_::160>>} | {:error, term()}
  def address do
    with {:ok, {signer, signer_opts}} <- Client.relayer_signer(),
         {:ok, [hex]} <- signer.accounts(signer_opts) do
      decode_address(hex)
    else
      {:ok, addresses} -> {:error, {:unexpected_relayer_accounts, length(addresses)}}
      {:error, _} = err -> err
    end
  end

  @doc """
  `address/0` memoized for 24h, for observability callers. Errors are not
  cached, so a signer that is unreachable is retried on the next call.

  The memo is bounded rather than permanent because a key rotation restarts the
  signer but not the API nodes: without an expiry, monitoring would watch the
  superseded address indefinitely while transactions used the new one, and the
  balance alerts would stay silent on the address actually being spent.
  `forget_cached_address/0` applies the same change immediately.
  """
  @spec cached_address() :: {:ok, <<_::160>>} | {:error, term()}
  def cached_address do
    now = System.monotonic_time(:millisecond)
    ttl = address_ttl_ms()

    # The age is compared at read time, not baked into the entry at write time,
    # so a shortened TTL applies to what is already memoized.
    case :persistent_term.get(@address_key, :miss) do
      {addr, written_at} when now - written_at < ttl ->
        {:ok, addr}

      _miss_or_expired ->
        with {:ok, addr} <- address() do
          # Written at most once per TTL: a put triggers a global GC scan.
          :persistent_term.put(@address_key, {addr, now})
          {:ok, addr}
        end
    end
  end

  @doc """
  Drops the memoized address, so the next read re-resolves it. The lever for a
  relayer key rotation, when waiting out the TTL is not acceptable.
  """
  @spec forget_cached_address() :: :ok
  def forget_cached_address do
    :persistent_term.erase(@address_key)
    :ok
  end

  @doc "The relayer's address as a lowercase `0x` string, for labels and logs."
  @spec hex(<<_::160>>) :: String.t()
  def hex(<<_::binary-size(20)>> = address), do: "0x" <> Base.encode16(address, case: :lower)

  # --- internals -------------------------------------------------------------

  # Both signers answer with a checksummed 0x string; monitoring wants raw bytes
  # so the label formatting happens in exactly one place.
  defp decode_address(hex) when is_binary(hex) do
    case Base.decode16(String.replace_prefix(hex, "0x", ""), case: :mixed) do
      {:ok, <<_::binary-size(20)>> = address} -> {:ok, address}
      _ -> {:error, {:invalid_relayer_address, hex}}
    end
  end

  defp decode_address(other), do: {:error, {:invalid_relayer_address, other}}

  defp address_ttl_ms,
    do: Application.get_env(:sovra, :relayer_address_ttl_ms, @address_ttl_ms)
end
