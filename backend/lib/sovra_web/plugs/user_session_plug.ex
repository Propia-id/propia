defmodule SovraWeb.Plugs.UserSessionPlug do
  @moduledoc """
  Plug that authenticates user requests via session JWT.
  Reads from `session` cookie first, falls back to `Authorization: Bearer` header.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  @doc """
  The session token on a request, from `cookie` or the `Bearer` header.

  Public, and taking the cookie name, so a controller can check for a session on
  a route this plug does not gate. That is how a private document requires one
  without closing the route to public documents, and it reads a different cookie
  because a cookie is only sent to its own path.
  """
  def session_token(conn, cookie \\ "session") do
    conn = fetch_cookies(conn)

    conn.cookies[cookie] ||
      case get_req_header(conn, "authorization") do
        ["Bearer " <> token] -> token
        _ -> nil
      end
  end

  def call(conn, _opts) do
    token = session_token(conn)

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
