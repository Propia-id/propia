defmodule SovraWeb.Cosigner.AuthController do
  use SovraWeb, :controller

  # Native mobile flow: verify ID token directly, issue session
  def auth(conn, %{"oauth_token" => oauth_token}) do
    case Sovra.Cosigner.authenticate_with_token(oauth_token) do
      {:ok, %{session_token: session_token, expires_at: expires_at}} ->
        json(conn, %{sessionToken: session_token, expiresAt: expires_at})

      {:error, :invalid_id_token} ->
        conn |> put_status(401) |> json(%{error: "invalid_oauth_token"})

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  # Browser-based flow: redirect to Google OAuth
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
