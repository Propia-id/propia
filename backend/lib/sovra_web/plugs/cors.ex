defmodule SovraWeb.Plugs.Cors do
  @moduledoc """
  `CORSPlug` with the origin allow-list resolved per request from
  `SovraWeb.AllowedOrigins`.

  Plugging `CORSPlug` directly does not work in a release: the endpoint
  initialises its pipeline at compile time, so `CORSPlug.init/1` reads
  `:cors_plug` config during `mix release` — long before `ISSUER_FRONTEND_URL`
  exists — and bakes the build-time default in. The API then answers preflights
  with no `access-control-allow-origin` header at all and every browser call
  from the issuer SPA fails.
  """

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    CORSPlug.call(conn, CORSPlug.init(origin: SovraWeb.AllowedOrigins.list()))
  end
end
