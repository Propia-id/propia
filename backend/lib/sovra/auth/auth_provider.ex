defmodule Sovra.Auth.AuthProvider do
  @moduledoc """
  Behaviour for OAuth authentication providers.
  V1 ships with GoogleAuthProvider. Adding a new provider means implementing this interface.
  """

  @callback get_authorization_url(state :: String.t()) ::
              {:ok, String.t()} | {:error, term()}

  @callback handle_callback(code :: String.t()) ::
              {:ok, %{sub: String.t(), email: String.t(), provider: String.t()}}
              | {:error, term()}

  @callback verify_id_token(token :: String.t()) ::
              {:ok, %{sub: String.t(), email: String.t()}} | {:error, term()}
end
