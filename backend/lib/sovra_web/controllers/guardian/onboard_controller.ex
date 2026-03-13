defmodule SovraWeb.Guardian.OnboardController do
  use SovraWeb, :controller

  def onboard(conn, %{"sovraAddress" => sovra_address, "oauthToken" => oauth_token}) do
    case Sovra.Guardian.onboard(sovra_address, oauth_token) do
      {:ok, %{recovery_public_key: _} = result} ->
        conn |> put_status(201) |> json(%{
          recoveryPublicKey: result.recovery_public_key,
          sessionToken: result.session_token
        })

      {:ok, %{sovra_address: _} = result} ->
        conn |> put_status(200) |> json(%{
          sovraAddress: result.sovra_address,
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
