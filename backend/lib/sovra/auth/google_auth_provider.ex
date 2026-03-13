defmodule Sovra.Auth.GoogleAuthProvider do
  @moduledoc """
  Google OAuth 2.0 authentication provider.
  Exchanges authorization codes for tokens and verifies Google ID tokens.
  """

  @behaviour Sovra.Auth.AuthProvider

  @google_auth_url "https://accounts.google.com/o/oauth2/v2/auth"
  @google_token_url "https://oauth2.googleapis.com/token"
  @google_jwks_url "https://www.googleapis.com/oauth2/v3/certs"
  @jwks_ttl 3600

  @impl true
  def get_authorization_url(state) do
    params =
      URI.encode_query(%{
        client_id: config(:google_client_id),
        redirect_uri: config(:google_redirect_uri),
        response_type: "code",
        scope: "openid email",
        state: state
      })

    {:ok, "#{@google_auth_url}?#{params}"}
  end

  @impl true
  def handle_callback(code) do
    body = %{
      code: code,
      client_id: config(:google_client_id),
      client_secret: config(:google_client_secret),
      redirect_uri: config(:google_redirect_uri),
      grant_type: "authorization_code"
    }

    case Req.post(@google_token_url, form: body) do
      {:ok, %{status: 200, body: %{"id_token" => id_token}}} ->
        case verify_id_token(id_token) do
          {:ok, claims} -> {:ok, Map.put(claims, :provider, "google")}
          error -> error
        end

      {:ok, %{body: body}} ->
        {:error, {:oauth_error, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end

  @impl true
  def verify_id_token(token) do
    with {:ok, jwks} <- fetch_google_jwks(),
         {:ok, claims} <- verify_jwt(token, jwks) do
      {:ok, %{sub: claims["sub"], email: claims["email"]}}
    end
  end

  defp fetch_google_jwks do
    case get_cached_jwks() do
      {:ok, jwks} -> {:ok, jwks}
      :miss -> fetch_and_cache_jwks()
    end
  end

  defp get_cached_jwks do
    case :persistent_term.get(:google_jwks_cache, nil) do
      {jwks, cached_at} when is_list(jwks) ->
        if System.system_time(:second) - cached_at < @jwks_ttl,
          do: {:ok, jwks},
          else: :miss

      _ ->
        :miss
    end
  end

  defp fetch_and_cache_jwks do
    case Req.get(@google_jwks_url) do
      {:ok, %{status: 200, body: %{"keys" => keys}}} ->
        jwks = Enum.map(keys, &JOSE.JWK.from_map/1)
        :persistent_term.put(:google_jwks_cache, {jwks, System.system_time(:second)})
        {:ok, jwks}

      _ ->
        {:error, :jwks_fetch_failed}
    end
  end

  defp verify_jwt(token, jwks) do
    # Try each key until one verifies
    result =
      Enum.find_value(jwks, :none, fn jwk ->
        case JOSE.JWT.verify_strict(jwk, ["RS256"], token) do
          {true, %JOSE.JWT{fields: fields}, _jws} ->
            if valid_google_claims?(fields), do: {:ok, fields}

          _ ->
            nil
        end
      end)

    case result do
      {:ok, _} = ok -> ok
      :none -> {:error, :invalid_id_token}
    end
  end

  defp valid_google_claims?(claims) do
    now = System.system_time(:second)

    claims["iss"] in ["accounts.google.com", "https://accounts.google.com"] and
      claims["aud"] in allowed_client_ids() and
      claims["exp"] > now and
      is_integer(claims["iat"]) and claims["iat"] <= now and
      claims["email_verified"] == true
  end

  defp allowed_client_ids do
    [
      config(:google_client_id),
      config(:google_ios_client_id),
      config(:google_android_client_id),
      config(:google_web_client_id)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp config(key), do: Application.get_env(:sovra, key)
end
