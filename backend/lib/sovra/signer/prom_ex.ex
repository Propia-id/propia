defmodule Sovra.Signer.PromEx do
  @moduledoc """
  Prometheus exporter for the signer role.

  Separate from `Sovra.PromEx`, whose plugins reach for the Repo, the Phoenix
  endpoint and the relayer — none of which exist in this tree. Only the build
  identity and BEAM internals are exported: the KMS verdict already reaches
  Prometheus through the API's readiness poll, as
  `sovra_health_dependency_up{dependency="signer_kms"}`.

  No `Plugins.Application`: its useful output here duplicates
  `Sovra.PromEx.BuildPlugin`, and the rest is an inventory of every dependency
  plus a `git_sha_info` reading "Git SHA not available", which is the metric
  this whole mechanism exists to replace.
  """

  use PromEx, otp_app: :sovra

  alias PromEx.Plugins

  @impl true
  def plugins do
    [
      Plugins.Beam,
      Sovra.PromEx.BuildPlugin
    ]
  end

  @impl true
  def dashboards, do: []

  @impl true
  def dashboard_assigns, do: []
end
