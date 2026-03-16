defmodule SovraWeb.Issuer.AuthController do
  use SovraWeb, :controller

  alias Sovra.Issuer.Accounts
  alias Sovra.Auth.IssuerSession

  @cookie_name "issuer_session"
  @cookie_opts [
    http_only: true,
    secure: true,
    same_site: "Strict",
    path: "/api/v1/issuer",
    max_age: 3600
  ]

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.authenticate(email, password) do
      {:ok, %{token: token, role: "admin"}} ->
        conn
        |> put_resp_cookie(@cookie_name, token, @cookie_opts)
        |> json(%{role: "admin"})

      {:ok, %{token: token, issuer: issuer}} ->
        conn
        |> put_resp_cookie(@cookie_name, token, @cookie_opts)
        |> json(%{
          issuer: %{id: issuer.id, name: issuer.name, did: issuer.did, status: issuer.status}
        })

      {:error, :invalid_credentials} ->
        conn |> put_status(401) |> json(%{error: "invalid_credentials"})
    end
  end

  def logout(conn, _params) do
    # Revoke the current session token if present
    conn = fetch_cookies(conn)

    if token = conn.cookies[@cookie_name] do
      IssuerSession.revoke(token)
    end

    conn
    |> delete_resp_cookie(@cookie_name, path: "/api/v1/issuer")
    |> json(%{ok: true})
  end
end
