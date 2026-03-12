defmodule Sovra.Auth.Session do
  @moduledoc """
  JWT-based session tokens for guardian authentication.
  Tokens are HMAC-SHA256 signed, 15-minute expiry, stateless.
  """

  @session_ttl 900

  def create(sovra_address) do
    now = System.system_time(:second)

    claims = %{
      "sub" => sovra_address,
      "scope" => "guardian",
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
        {true, %JOSE.JWT{fields: %{"sub" => sub, "scope" => "guardian", "exp" => exp}}, _jws} ->
          if exp > System.system_time(:second) do
            {:ok, %{sovra_address: sub}}
          else
            {:error, :expired}
          end

        _ ->
          {:error, :invalid}
      end
    rescue
      _ -> {:error, :invalid}
    end
  end

  defp signing_key do
    secret = Application.fetch_env!(:sovra, :session_secret)
    JOSE.JWK.from_oct(secret)
  end
end
