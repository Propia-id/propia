defmodule Sovra.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    # One release, two roles. `SERVICE=signer` boots a slim tree (the KMS signer
    # HTTP service only — no Repo, no Oban, no Phoenix endpoint) so the dedicated
    # signer box carries the least possible surface. Everything else (default) is
    # the full API node.
    service = System.get_env("SERVICE", "api")

    if service != "signer" do
      attach_oban_logger()
      SovraWeb.Telemetry.attach_handlers()
    end

    children = children(service)

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Sovra.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp children("signer") do
    [{Bandit, plug: Sovra.Signer.Router, scheme: :http, port: signer_port()}]
  end

  defp children(_api) do
    [
      Sovra.Repo,
      {DNSCluster, query: Application.get_env(:sovra, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Sovra.PubSub},
      {Finch, name: Sovra.Finch},
      {Task.Supervisor, name: Sovra.TaskSupervisor},
      {Oban, Application.fetch_env!(:sovra, Oban)},
      Sovra.Auth.TokenDenylist,
      Sovra.DID.DocumentCache,
      SovraWeb.Endpoint
    ]
    |> maybe_add_key_store()
  end

  defp signer_port, do: Application.get_env(:sovra, :signer_service, [])[:port] || 4001

  # Per-job detail for `journalctl -u sovra`, and deliberately NOT for New Relic:
  # the same facts are already on Transaction events as `oban.worker`,
  # `oban.queue` and `oban.job.result`, which is what the provisioning and
  # mailer alert conditions read.
  #
  # `encode: false` is what keeps them out. Oban's default logger otherwise
  # emits its payload as a JSON string; New Relic parses that into attributes
  # and, since the payload carries no `message` key, files thousands of
  # blank-message records — two per job, plus two a minute forever from the
  # ExpiredSessionsSweeper cron whether or not anything is happening. With
  # `encode: false` the log is a `{:report, map}` whose domain is
  # `[:elixir, :oban]`, and NewRelic.LogsInContext only forwards a report when
  # the domain is exactly `[:elixir]` — so these stay on the box, while the
  # default handler still formats them into journald.
  defp attach_oban_logger do
    :ok = Oban.Telemetry.attach_default_logger(level: :info, encode: false)
  rescue
    # attach_default_logger/1 raises if the handler is already attached, which
    # happens when the app restarts inside one VM (releases, `iex -S mix`).
    ArgumentError -> :ok
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
          raise "DatabaseKeyStore is not allowed in production. Use KmsKeyStore instead."
        end

        Logger.info("Using DatabaseKeyStore (PostgreSQL)")
        children

      Sovra.Crypto.KmsKeyStore ->
        # Stateless — signing is an authenticated RPC to the signer service
        # (which owns the KMS calls); nothing to supervise on the API node.
        Logger.info("Using KmsKeyStore (AWS KMS via signer service)")
        children

      other ->
        Logger.info("Using key store: #{inspect(other)}")
        children
    end
  end
end
