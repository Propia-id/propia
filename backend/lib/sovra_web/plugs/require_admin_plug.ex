defmodule SovraWeb.Plugs.RequireAdminPlug do
  @moduledoc """
  Plug that restricts access to admin-only routes.
  Must be used after UserSessionPlug.
  """

  use Sovra.Log

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  def call(conn, _opts) do
    case conn.assigns[:current_user] do
      %{is_admin: true} ->
        conn

      other ->
        Log.event(:warning, "platform admin required",
          event: "authz.denied",
          reason: if(other, do: :insufficient_role, else: :no_session),
          required_role: "platform_admin",
          path: conn.request_path
        )

        conn |> put_status(403) |> json(%{error: "admin_required"}) |> halt()
    end
  end
end
