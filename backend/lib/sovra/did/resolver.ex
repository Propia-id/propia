defmodule Sovra.DID.Resolver do
  @moduledoc """
  DID resolution — resolves did:sovra identifiers to DID documents.
  """

  @doc """
  Resolves a DID string to a DID document.
  """
  def resolve(_did) do
    {:error, :not_implemented}
  end
end
