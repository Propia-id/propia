defmodule Sovra.Auth.UserSession do
  @moduledoc """
  Short-lived JWT access tokens for end-user authentication.
  Tokens are HMAC-SHA256 signed, 1-hour expiry, with revocation support
  via the token denylist.

  `create/3` and `revoke/1` put the caller on the request's log context.
  `UserSessionPlug` can only name a request that *presents* a session, which
  leaves login, registration, refresh and logout unattributed.
  """

  use Sovra.Log

  alias Sovra.Auth.TokenDenylist

  @session_ttl 3600

  def create(user_id, workspace_id, is_admin \\ false) do
    Log.put_context(user_id: user_id, workspace_id: workspace_id)

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
        Log.event(:warning, "session token rejected",
          event: "auth.session.rejected",
          token_kind: :dashboard,
          reason: :verification_raised,
          detail: Log.reason(e)
        )

        {:error, :invalid}
    end
  end

  @doc "Revoke the given token so it cannot be used again."
  def revoke(token) do
    jwk = signing_key()

    try do
      case JOSE.JWT.verify_strict(jwk, ["HS256"], token) do
        {true, %JOSE.JWT{fields: %{"jti" => jti, "exp" => exp} = fields}, _jws} ->
          TokenDenylist.revoke(jti, exp)

          # After the revocation: the rescue below would turn a raise in here
          # into a silent `:ok` for a live token. No `workspace_id` either,
          # since `WorkspaceController.switch/2` revokes the old session right
          # after minting the new one, and the stale claim would win.
          Log.put_context(user_id: fields["sub"])
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
