defmodule SovraWeb.Issuer.AuthController do
  use SovraWeb, :controller

  alias Sovra.Issuer.Accounts

  def register(conn, %{"email" => email, "password" => password, "issuer_name" => issuer_name}) do
    case Accounts.register(email, password, issuer_name) do
      {:ok, %{token: token, issuer: issuer}} ->
        conn
        |> put_status(201)
        |> json(%{
          token: token,
          issuer: %{id: issuer.id, name: issuer.name, did: issuer.did}
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        conn |> put_status(422) |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: inspect(reason)})
    end
  end

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.authenticate(email, password) do
      {:ok, %{token: token, issuer: issuer}} ->
        conn
        |> json(%{
          token: token,
          issuer: %{id: issuer.id, name: issuer.name, did: issuer.did}
        })

      {:error, :invalid_credentials} ->
        conn |> put_status(401) |> json(%{error: "invalid_credentials"})
    end
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
