defmodule Sovra.Auth.Session do
  @moduledoc """
  JWT-based session tokens for guardian authentication.
  Tokens are HMAC-SHA256 signed, 15-minute expiry, stateless.
  """

  require Logger

  @session_ttl 900

  def create(sovra_address) do
    now = System.system_time(:second)

    claims = %{
      "sub" => sovra_address,
      "scope" => "guardian",
      "iss" => "sovra-guardian",
      "aud" => "sovra-guardian",
      "jti" => generate_jti(),
      "iat" => now,
      "exp" => now + @session_ttl
    }

    jwk = signing_key()
    jws = %{"alg" => "HS256"}
    {_, token} = JOSE.JWT.sign(jwk, jws, claims) |> JOSE.JWS.compact()
    {:ok, token}
  end

  def verify(token) do
    jwk = signing_key()

    try do
      case JOSE.JWT.verify_strict(jwk, ["HS256"], token) do
        {true,
         %JOSE.JWT{
           fields: %{
             "sub" => sub,
             "scope" => "guardian",
             "iss" => "sovra-guardian",
             "aud" => "sovra-guardian",
             "iat" => iat,
             "exp" => exp
           }
         }, _jws} ->
          if exp > System.system_time(:second) do
            {:ok, %{sovra_address: sub, iat: iat}}
          else
            {:error, :expired}
          end

        _ ->
          {:error, :invalid}
      end
    rescue
      e in [ArgumentError, FunctionClauseError, ErlangError] ->
        Logger.warning("Session verification failed: #{inspect(e)}")
        {:error, :invalid}
    end
  end

  defp signing_key do
    secret = Application.fetch_env!(:sovra, :session_secret)
    JOSE.JWK.from_oct(secret)
  end

  defp generate_jti, do: Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
end
