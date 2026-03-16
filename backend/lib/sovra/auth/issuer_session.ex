defmodule Sovra.Auth.IssuerSession do
  @moduledoc """
  JWT-based session tokens for issuer dashboard authentication.
  Tokens are HMAC-SHA256 signed, 1-hour expiry, stateless.
  """

  require Logger

  @session_ttl 3600

  def create(account_id, issuer_id, role \\ "issuer") do
    now = System.system_time(:second)

    claims = %{
      "sub" => account_id,
      "issuer_id" => issuer_id,
      "role" => role,
      "scope" => "issuer_admin",
      "iss" => "sovra-issuer",
      "aud" => "sovra-issuer",
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
           fields:
             %{
               "sub" => sub,
               "scope" => "issuer_admin",
               "iss" => "sovra-issuer",
               "aud" => "sovra-issuer",
               "exp" => exp
             } = fields
         }, _jws} ->
          if exp > System.system_time(:second) do
            {:ok,
             %{
               account_id: sub,
               issuer_id: fields["issuer_id"],
               role: fields["role"] || "issuer"
             }}
          else
            {:error, :expired}
          end

        _ ->
          {:error, :invalid}
      end
    rescue
      e in [ArgumentError, FunctionClauseError, ErlangError] ->
        Logger.warning("Issuer session verification failed: #{inspect(e)}")
        {:error, :invalid}
    end
  end

  defp signing_key do
    secret = Application.fetch_env!(:sovra, :session_secret)
    JOSE.JWK.from_oct(secret)
  end

  defp generate_jti, do: Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
end
