defmodule Sovra.PromEx do
  @moduledoc """
  Prometheus exporter for the API role; the signer role has nothing to export.

  Dashboards and alert rules are file-provisioned, so PromEx's Grafana keys are
  never set. `/metrics` is served by a Bandit listener in the supervision tree,
  since PromEx's own server is Plug.Cowboy-only.
  """

  use PromEx, otp_app: :sovra

  alias PromEx.Plugins

  @impl true
  def plugins do
    [
      Plugins.Beam,
      {Plugins.Application, otp_app: :sovra},
      {Plugins.Phoenix, endpoint: SovraWeb.Endpoint, router: SovraWeb.Router},
      # Carries queue time, which is the pool-saturation signal.
      {Plugins.Ecto, repos: [Sovra.Repo]},
      Sovra.PromEx.RelayerPlugin
    ]
  end

  @impl true
  def dashboards, do: []

  @impl true
  def dashboard_assigns, do: []
end
