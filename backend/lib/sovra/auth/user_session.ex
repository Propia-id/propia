defmodule Sovra.Auth.UserSession do
  @moduledoc """
  Short-lived JWT access tokens for end-user authentication.
  Tokens are HMAC-SHA256 signed, 1-hour expiry, with revocation support
  via the token denylist.
  """

  require Logger

  alias Sovra.Auth.TokenDenylist

  @session_ttl 3600

  def create(user_id, workspace_id, is_admin \\ false) do
    now = System.system_time(:second)

    claims = %{
      "sub" => user_id,
      "workspace_id" => workspace_id,
      "is_admin" => is_admin,
      "scope" => "user",
      "iss" => "sovra",
      "aud" => "sovra",
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
               "scope" => "user",
               "iss" => "sovra",
               "aud" => "sovra",
               "exp" => exp
             } = fields
         }, _jws} ->
          cond do
            exp <= System.system_time(:second) ->
              {:error, :expired}

            TokenDenylist.revoked?(fields["jti"]) ->
              {:error, :revoked}

            true ->
              {:ok,
               %{
                 user_id: sub,
                 workspace_id: fields["workspace_id"],
                 is_admin: fields["is_admin"] || false
               }}
          end

        _ ->
          {:error, :invalid}
      end
    rescue
      e in [ArgumentError, FunctionClauseError, ErlangError] ->
        Logger.warning("User session verification failed: #{inspect(e)}")
        {:error, :invalid}
    end
  end

  @doc "Revoke the given token so it cannot be used again."
  def revoke(token) do
    jwk = signing_key()

    try do
      case JOSE.JWT.verify_strict(jwk, ["HS256"], token) do
        {true, %JOSE.JWT{fields: %{"jti" => jti, "exp" => exp}}, _jws} ->
          TokenDenylist.revoke(jti, exp)
          :ok

        _ ->
          :ok
      end
    rescue
      _ -> :ok
    end
  end

  defp signing_key do
    Sovra.Auth.KeyDerivation.derive_key(:user_session) |> JOSE.JWK.from_oct()
  end

  defp generate_jti, do: Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
end
