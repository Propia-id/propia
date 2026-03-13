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
        Logger.info("Starting SoftwareKeyStore (dev/test only — use HSM/KMS in production)")
        children ++ [Sovra.Crypto.SoftwareKeyStore]

      _ ->
        children
    end
  end
end
