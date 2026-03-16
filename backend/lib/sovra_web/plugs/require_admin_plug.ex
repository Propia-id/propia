defmodule SovraWeb.Plugs.RequireAdminPlug do
  @moduledoc """
  Plug that restricts access to admin-only routes.
  Must be used after IssuerSessionPlug.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  def call(conn, _opts) do
    case conn.assigns[:current_issuer_account] do
      %{role: "admin"} ->
        conn

      _ ->
        conn |> put_status(403) |> json(%{error: "admin_required"}) |> halt()
    end
  end
end
