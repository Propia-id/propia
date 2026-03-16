defmodule SovraWeb.Issuer.AuthController do
  use SovraWeb, :controller

  alias Sovra.Issuer.Accounts

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.authenticate(email, password) do
      {:ok, %{token: token, role: "admin"}} ->
        conn |> json(%{token: token, role: "admin"})

      {:ok, %{token: token, issuer: issuer}} ->
        conn
        |> json(%{
          token: token,
          issuer: %{id: issuer.id, name: issuer.name, did: issuer.did, status: issuer.status}
        })

      {:error, :invalid_credentials} ->
        conn |> put_status(401) |> json(%{error: "invalid_credentials"})
    end
  end
end
