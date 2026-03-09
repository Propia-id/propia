defmodule SovraWeb.Cosigner.AuthController do
  use SovraWeb, :controller

  def auth(conn, %{"sovraAddress" => sovra_address}) do
    case Sovra.Cosigner.get_auth_url(sovra_address) do
      {:ok, url} ->
        json(conn, %{authorizationUrl: url})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def auth(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end

  def callback(conn, %{"code" => code, "state" => state}) do
    case Sovra.Cosigner.handle_auth_callback(code, state) do
      {:ok, session_token} ->
        json(conn, %{session: session_token})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, :oauth_mismatch} ->
        conn |> put_status(403) |> json(%{error: "oauth_identity_mismatch"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def callback(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end
end
