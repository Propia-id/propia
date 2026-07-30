defmodule SovraWeb.AllowedOrigins do
  @moduledoc """
  The browser-origin allow-list, shared by `SovraWeb.Plugs.Cors` (which sends
  the CORS headers) and `SovraWeb.Plugs.OriginCheckPlug` (which rejects
  cross-origin mutations). One source of truth so the two cannot disagree.

  Resolved on every request, deliberately. `ISSUER_FRONTEND_URL` is only known
  when the release boots, but the endpoint's plug pipeline is initialised at
  compile time (`plug_init_mode` defaults to `:compile` outside dev/test), so a
  plug that reads configuration in `init/1` captures the build-time default and
  ignores `runtime.exs` entirely.
  """

  @doc """
  Allowed browser origins: the issuer SPA plus any extras. Empty when nothing is
  configured — the caller must treat that as "allow nothing", never as a
  wildcard.
  """
  def list do
    base = Application.get_env(:sovra, :issuer_frontend_url, "")
    extras = Application.get_env(:sovra, :additional_allowed_origins, [])

    [base | extras]
    |> Enum.reject(&(&1 in [nil, ""]))
  end
end
