defmodule SovraWeb.Plugs.IssuerSessionPlug do
  @moduledoc """
  Plug that authenticates issuer dashboard requests via session JWT.
  Reads from `issuer_session` cookie first, falls back to `Authorization: Bearer` header.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  def call(conn, _opts) do
    conn = fetch_cookies(conn)

    token =
      conn.cookies["issuer_session"] ||
        case get_req_header(conn, "authorization") do
          ["Bearer " <> t] -> t
          _ -> nil
        end

    if token do
      case Sovra.Auth.IssuerSession.verify(token) do
        {:ok, %{account_id: account_id, issuer_id: issuer_id, role: role}} ->
          conn
          |> assign(:current_issuer_account, %{
            account_id: account_id,
            issuer_id: issuer_id,
            role: role
          })
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
