defmodule Sovra.Auth.TokenDenylist do
  @moduledoc """
  ETS-based token denylist for revoking JWTs before expiry.

  Stores {jti, expires_at} pairs. Entries are automatically cleaned up
  every 5 minutes once their expiry has passed (no point keeping them
  after the token would have expired naturally).
  """

  use GenServer

  @table :token_denylist
  @cleanup_interval :timer.minutes(5)

  # ── Client API ──────────────────────────────────────────────

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc "Add a token's jti to the denylist. `expires_at` is the token's `exp` claim (unix seconds)."
  @spec revoke(String.t(), integer()) :: :ok
  def revoke(jti, expires_at) do
    :ets.insert(@table, {jti, expires_at})
    :ok
  end

  @doc "Check if a jti has been revoked."
  @spec revoked?(String.t()) :: boolean()
  def revoked?(jti) do
    :ets.member(@table, jti)
  end

  # ── GenServer callbacks ─────────────────────────────────────

  @impl true
  def init(_) do
    :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
    schedule_cleanup()
    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now = System.system_time(:second)

    :ets.select_delete(@table, [{{:"$1", :"$2"}, [{:<, :"$2", now}], [true]}])

    schedule_cleanup()
    {:noreply, state}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end
end
