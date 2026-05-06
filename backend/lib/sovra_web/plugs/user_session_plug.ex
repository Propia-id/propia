defmodule SovraWeb.Plugs.UserSessionPlug do
  @moduledoc """
  Plug that authenticates user requests via session JWT.
  Reads from `session` cookie first, falls back to `Authorization: Bearer` header.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  def call(conn, _opts) do
    conn = fetch_cookies(conn)

    token =
      conn.cookies["session"] ||
        case get_req_header(conn, "authorization") do
          ["Bearer " <> t] -> t
          _ -> nil
        end

    if token do
      case Sovra.Auth.UserSession.verify(token) do
        {:ok, %{user_id: user_id, workspace_id: workspace_id, is_admin: is_admin}} ->
          conn
          |> assign(:current_user, %{
            user_id: user_id,
            workspace_id: workspace_id,
            is_admin: is_admin
          })
          |> assign(:current_workspace_id, workspace_id)
          |> assign(:current_auth_method, :session)
          |> assign(:current_session_token, token)

        {:error, :expired} ->
          conn |> put_status(401) |> json(%{error: "session_expired"}) |> halt()

        {:error, :revoked} ->
          conn |> put_status(401) |> json(%{error: "session_revoked"}) |> halt()

        {:error, _} ->
          conn |> put_status(401) |> json(%{error: "invalid_session"}) |> halt()
      end
    else
      conn |> put_status(401) |> json(%{error: "missing_authorization"}) |> halt()
    end
  end
end
