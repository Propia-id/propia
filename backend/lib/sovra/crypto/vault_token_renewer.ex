defmodule Sovra.Crypto.VaultTokenRenewer do
  @moduledoc """
  Periodically renews the OpenBao/Vault periodic token to prevent expiration.

  The token value itself doesn't change — renewal just extends the TTL.
  Renews at half the configured interval to ensure the token never expires
  even if a single renewal fails.
  """

  use GenServer

  require Logger

  # Default: renew every 48 hours (for a 96h-period token)
  @default_interval_ms 48 * 60 * 60 * 1000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    interval = renewal_interval()
    schedule_renewal(interval)
    Logger.info("VaultTokenRenewer started, renewing every #{div(interval, 60_000)} minutes")
    {:ok, %{interval: interval}}
  end

  @impl true
  def handle_info(:renew, state) do
    case renew_token() do
      :ok ->
        Logger.debug("Vault token renewed successfully")

      {:error, reason} ->
        Logger.warning("Vault token renewal failed: #{inspect(reason)}")
    end

    schedule_renewal(state.interval)
    {:noreply, state}
  end

  defp schedule_renewal(interval) do
    Process.send_after(self(), :renew, interval)
  end

  defp renew_token do
    config = Application.fetch_env!(:sovra, :vault)
    url = Keyword.fetch!(config, :url)
    token = Keyword.fetch!(config, :token)

    case Req.post("#{url}/v1/auth/token/renew-self",
           headers: [{"x-vault-token", token}],
           json: %{}
         ) do
      {:ok, %{status: 200}} -> :ok
      {:ok, %{status: status, body: body}} -> {:error, {:vault_renew_error, status, body}}
      {:error, reason} -> {:error, {:vault_renew_error, reason}}
    end
  end

  defp renewal_interval do
    case Application.get_env(:sovra, :vault) do
      nil -> @default_interval_ms
      config -> Keyword.get(config, :token_renewal_interval_ms, @default_interval_ms)
    end
  end
end
