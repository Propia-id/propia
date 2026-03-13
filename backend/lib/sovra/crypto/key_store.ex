defmodule Sovra.Crypto.KeyStore do
  @moduledoc """
  Behaviour for cryptographic key storage backends.
  Production uses HSM/KMS; development uses SoftwareKeyStore.
  """

  @callback generate_key(holder_id :: String.t()) ::
              {:ok, %{key_id: String.t(), public_key_x: binary(), public_key_y: binary()}}
              | {:error, term()}

  @callback sign(key_id :: String.t(), hash :: binary()) ::
              {:ok, %{r: binary(), s: binary()}} | {:error, term()}

  @callback store_key(key_id :: String.t(), private_key :: binary()) :: :ok | {:error, term()}

  @callback delete_key(key_id :: String.t()) :: :ok | {:error, term()}
end
