defmodule Sovra.Crypto.P256 do
  @moduledoc """
  P-256 (secp256r1) key operations — generation, signing, verification.
  """

  @doc """
  Generates a new P-256 key pair.
  """
  def generate_key_pair do
    {:error, :not_implemented}
  end

  @doc """
  Signs data with a P-256 private key.
  """
  def sign(_data, _private_key) do
    {:error, :not_implemented}
  end

  @doc """
  Verifies a P-256 signature.
  """
  def verify(_data, _signature, _public_key) do
    {:error, :not_implemented}
  end
end
