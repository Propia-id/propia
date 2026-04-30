defmodule Sovra.DID.Resolver do
  @moduledoc """
  DID resolution dispatcher. Routes a DID string to the resolver for its
  method. Today only `did:sovra:` is supported — adding `did:web` or
  `did:key` is a matter of adding a clause here and a method module.
  """

  alias Sovra.DID.SovraMethod

  @type jwk :: SovraMethod.jwk()

  @spec resolve(String.t()) :: {:ok, [jwk]} | {:error, atom}
  def resolve("did:sovra:" <> _ = did), do: SovraMethod.resolve(did)
  def resolve(_), do: {:error, :unsupported_did_method}
end
