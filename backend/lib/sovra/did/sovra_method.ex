defmodule Sovra.DID.SovraMethod do
  @moduledoc """
  did:sovra method — creates and manages Sovra-specific DID documents.
  """

  @doc """
  Creates a new did:sovra DID for the given Ethereum address.
  """
  def create(_address) do
    {:error, :not_implemented}
  end
end
