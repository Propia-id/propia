defmodule Sovra.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    children =
      [
        SovraWeb.Telemetry,
        Sovra.Repo,
        {DNSCluster, query: Application.get_env(:sovra, :dns_cluster_query) || :ignore},
        {Phoenix.PubSub, name: Sovra.PubSub},
        {Finch, name: Sovra.Finch},
        Sovra.Auth.TokenDenylist,
        SovraWeb.Endpoint
      ]
      |> maybe_add_key_store()

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Sovra.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    SovraWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp maybe_add_key_store(children) do
    case Application.get_env(:sovra, :key_store) do
      Sovra.Crypto.SoftwareKeyStore ->
        Logger.info("Starting SoftwareKeyStore (dev/test only)")
        children ++ [Sovra.Crypto.SoftwareKeyStore]

      Sovra.Crypto.DatabaseKeyStore ->
        if Application.get_env(:sovra, :env) == :prod do
          raise "DatabaseKeyStore is not allowed in production. Use VaultKeyStore instead."
        end

        Logger.info("Using DatabaseKeyStore (PostgreSQL)")
        children

      Sovra.Crypto.VaultKeyStore ->
        Logger.info("Using VaultKeyStore (OpenBao Transit)")
        children ++ [Sovra.Crypto.VaultTokenRenewer]

      other ->
        Logger.info("Using key store: #{inspect(other)}")
        children
    end
  end
end
