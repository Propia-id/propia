defmodule Sovra.DID.Resolver do
  @moduledoc """
  DID resolution dispatcher. Routes a DID string to the resolver for its
  method. Supports `did:sovra:` (on-chain wallet read) and
  `did:quarkid:sovra:` (HTTPS resolver at node.sovra.io). Adding `did:web`
  or `did:key` is a matter of adding a clause here and a method module.
  """

  alias Sovra.DID.{QuarkidSovraMethod, SovraMethod}

  @type jwk :: SovraMethod.jwk() | QuarkidSovraMethod.jwk()

  @spec resolve(String.t()) :: {:ok, [jwk]} | {:error, atom}
  def resolve("did:sovra:" <> _ = did), do: SovraMethod.resolve(did)
  def resolve("did:quarkid:sovra:" <> _ = did), do: QuarkidSovraMethod.resolve(did)
  def resolve(_), do: {:error, :unsupported_did_method}
end
