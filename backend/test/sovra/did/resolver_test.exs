defmodule Sovra.DID.ResolverTest do
  use ExUnit.Case, async: true

  alias Sovra.DID.Resolver

  describe "resolve/1" do
    test "delegates did:sovra: to SovraMethod" do
      # SovraMethod requires WalletReader / chain RPC for full success, so
      # we just confirm the dispatcher reaches it (via a non-success path
      # that doesn't touch the chain — malformed body).
      assert {:error, :invalid_did} = Resolver.resolve("did:sovra:not-an-eoa")
    end

    test "rejects unsupported methods" do
      assert {:error, :unsupported_did_method} = Resolver.resolve("did:web:example.com")
      assert {:error, :unsupported_did_method} = Resolver.resolve("did:key:abc")
      assert {:error, :unsupported_did_method} = Resolver.resolve("not-a-did")
    end
  end
end
