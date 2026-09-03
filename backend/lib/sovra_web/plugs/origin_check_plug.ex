defmodule SovraWeb.Plugs.OriginCheckPlug do
  @moduledoc """
  CSRF defense-in-depth for cookie-authed mutations. On state-changing
  HTTP methods (POST/PATCH/PUT/DELETE), if an `Origin` header is present
  it must match the configured allow-list. Same-origin requests that omit
  `Origin` (rare but possible — server-to-server, some clients) are
  allowed through; CORSPlug already gates cross-origin browser traffic
  via preflight.
  """

  use Sovra.Log

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  @safe_methods ~w(GET HEAD OPTIONS)

  def init(opts), do: opts

  def call(%Plug.Conn{method: method} = conn, _opts) when method in @safe_methods, do: conn

  def call(conn, _opts) do
    case get_req_header(conn, "origin") do
      [] ->
        conn

      [origin] ->
        if origin in allowed_origins() do
          conn
        else
          reject(conn, origin, :not_allowed)
        end

      _ ->
        reject(conn, nil, :multiple_origin_headers)
    end
  end

  # `origin` is logged because a rejection is far more often a stale
  # ISSUER_FRONTEND_URL than an attack, and the value is the only way to tell
  # the two apart.
  defp reject(conn, origin, reason) do
    Log.event(:warning, "origin rejected",
      event: "auth.origin.rejected",
      reason: reason,
      origin: origin,
      method: conn.method,
      path: conn.request_path
    )

    conn |> put_status(403) |> json(%{error: "origin_not_allowed"}) |> halt()
  end

  defp allowed_origins, do: SovraWeb.AllowedOrigins.list()
end
