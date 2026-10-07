defmodule Sovra.Ethereum.SubmitLock do
  @moduledoc """
  One relayer submission at a time, across every node.

  Every on-chain write is paid for by one relayer key, so every write needs the
  next nonce of one account. Two writes that pick their nonce at the same time
  pick the same one, and the node rejects one of them or lets it replace the
  other. Oban limits concurrency per node only, and there are several API nodes,
  so the lock lives in Postgres, which they all share: a transaction-scoped
  advisory lock, keyed by the relayer address.

  Only the submission is held under it — read the nonce, sign, send. The receipt
  is awaited after the lock is released, so several transactions can be in
  flight at once with consecutive nonces.

  Waiters try the lock and back off rather than block on it. A process blocked
  in `pg_advisory_xact_lock` keeps its pooled connection the whole time, and
  with a node's chain and provisioning jobs all waiting there would be none
  left for requests. Only the holder keeps one.
  """

  alias Sovra.Repo

  # Waiting for the lock: other submissions only, each a few RPC calls and one
  # signature, so a minute means something is wrong. Overridable only so a test
  # can see a held lock time out.
  @wait_timeout_ms 60_000

  # Holding it: the submission, whose slowest part is the KMS signer and its own
  # 15s timeout.
  @hold_timeout_ms 60_000

  # Between tries, plus up to as much again of jitter, so waiters do not retry
  # in step.
  @retry_ms 100

  @busy {__MODULE__, :busy}

  @doc """
  Runs `fun` holding the submission lock for `relayer_address`. `fun` returns
  `{:ok, value}` or `{:error, reason}`, and so does this. A lock that cannot be
  had in time is `{:error, :relayer_lock_unavailable}` rather than an
  exception, so a job's failure path still runs.
  """
  @spec run(String.t(), (-> {:ok, term()} | {:error, term()})) :: {:ok, term()} | {:error, term()}
  def run(relayer_address, fun) when is_binary(relayer_address) do
    deadline = System.monotonic_time(:millisecond) + wait_timeout_ms()
    attempt(key(relayer_address), fun, deadline)
  end

  defp attempt(key, fun, deadline) do
    case try_run(key, fun) do
      {:error, @busy} ->
        if System.monotonic_time(:millisecond) >= deadline do
          {:error, :relayer_lock_unavailable}
        else
          Process.sleep(@retry_ms + :rand.uniform(@retry_ms))
          attempt(key, fun, deadline)
        end

      result ->
        result
    end
  end

  defp try_run(key, fun) do
    Repo.transaction(
      fn ->
        case Repo.query!("SELECT pg_try_advisory_xact_lock($1)", [key]) do
          %{rows: [[true]]} ->
            case fun.() do
              {:ok, value} -> value
              {:error, reason} -> Repo.rollback(reason)
            end

          %{rows: [[false]]} ->
            Repo.rollback(@busy)
        end
      end,
      timeout: @hold_timeout_ms
    )
  rescue
    DBConnection.ConnectionError -> {:error, :relayer_lock_unavailable}
  end

  # Advisory locks take a bigint. Derived from the address, lowercased because
  # the signers answer with a checksummed one, so it cannot collide with another
  # relayer's lock, or with a lock keyed by anything other than this string.
  @doc false
  def key(relayer_address) do
    <<key::signed-64, _rest::binary>> =
      :crypto.hash(:sha256, "sovra:relayer-submit:" <> String.downcase(relayer_address))

    key
  end

  defp wait_timeout_ms,
    do: Application.get_env(:sovra, :submit_lock_wait_timeout_ms, @wait_timeout_ms)
end
