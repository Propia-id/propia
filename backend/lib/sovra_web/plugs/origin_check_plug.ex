defmodule SovraWeb.Plugs.OriginCheckPlug do
  @moduledoc """
  CSRF defense-in-depth for cookie-authed mutations. On state-changing
  HTTP methods (POST/PATCH/PUT/DELETE), if an `Origin` header is present
  it must match the configured allow-list. Same-origin requests that omit
  `Origin` (rare but possible — server-to-server, some clients) are
  allowed through; CORSPlug already gates cross-origin browser traffic
  via preflight.
  """

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
          conn |> put_status(403) |> json(%{error: "origin_not_allowed"}) |> halt()
        end

      _ ->
        conn |> put_status(403) |> json(%{error: "origin_not_allowed"}) |> halt()
    end
  end

  defp allowed_origins, do: SovraWeb.AllowedOrigins.list()
end
