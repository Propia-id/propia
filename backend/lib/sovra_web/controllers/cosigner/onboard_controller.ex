defmodule SovraWeb.Cosigner.OnboardController do
  use SovraWeb, :controller

  def onboard(conn, %{"sovraAddress" => sovra_address, "oauthToken" => oauth_token}) do
    case Sovra.Cosigner.onboard(sovra_address, oauth_token) do
      {:ok, result} ->
        conn |> put_status(201) |> json(%{
          recoveryPublicKey: result.recovery_public_key,
          sessionToken: result.session_token
        })

      {:error, :already_onboarded} ->
        conn |> put_status(409) |> json(%{error: "already_onboarded"})

      {:error, :invalid_id_token} ->
        conn |> put_status(401) |> json(%{error: "invalid_oauth_token"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end

  def onboard(conn, _params) do
    conn |> put_status(400) |> json(%{error: "missing_required_fields"})
  end
end
