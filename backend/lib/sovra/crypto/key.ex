defmodule Sovra.Crypto.Key do
  @moduledoc """
  Facade for key management. Delegates to the configured KeyStore implementation.
  """

  def generate_key(holder_id), do: impl().generate_key(holder_id)
  def store_key(key_id, private_key), do: impl().store_key(key_id, private_key)
  def sign(key_id, hash), do: impl().sign(key_id, hash)
  def delete_key(key_id), do: impl().delete_key(key_id)

  defp impl, do: Application.get_env(:sovra, :key_store, Sovra.Crypto.SoftwareKeyStore)
end
