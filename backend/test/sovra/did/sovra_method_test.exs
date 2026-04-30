defmodule Sovra.DID.SovraMethodTest do
  use ExUnit.Case, async: true

  alias Sovra.DID.SovraMethod

  describe "resolve/1 — DID parsing" do
    test "rejects malformed body (not 0x + 40 hex)" do
      assert {:error, :invalid_did} = SovraMethod.resolve("did:sovra:foo")
      assert {:error, :invalid_did} = SovraMethod.resolve("did:sovra:0xabc")

      assert {:error, :invalid_did} =
               SovraMethod.resolve("did:sovra:0x" <> String.duplicate("z", 40))
    end

    test "rejects non-sovra methods" do
      assert {:error, :unsupported_did_method} = SovraMethod.resolve("did:web:example.com")
      assert {:error, :unsupported_did_method} = SovraMethod.resolve("not-a-did")
    end

    # Note: full chain-success / deactivated / RPC-error paths exercise
    # WalletReader against a live L2 and are integration-tested via the
    # higher-level Verifier flow with a stub resolver. Unit-stubbing
    # WalletReader here would require an injectable interface that's not
    # worth the surface area for two helpers.
  end
end
