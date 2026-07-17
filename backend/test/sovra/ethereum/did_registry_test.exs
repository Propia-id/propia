defmodule Sovra.Ethereum.DIDRegistryTest do
  use ExUnit.Case, async: true

  alias Sovra.Ethereum.DIDRegistry

  describe "did_already_exists?/1" do
    # keccak256("DIDAlreadyExists()")[0..3]
    @selector "0x338c38da"

    test "matches the selector in the JSON-RPC error data field" do
      assert DIDRegistry.did_already_exists?(%{
               "code" => 3,
               "data" => @selector,
               "message" => "execution reverted"
             })
    end

    test "matches the selector embedded in the message (observed production shape)" do
      assert DIDRegistry.did_already_exists?(%{"message" => "execution reverted: " <> @selector})
    end

    test "matches a bare string reason" do
      assert DIDRegistry.did_already_exists?("execution reverted: " <> @selector)
    end

    test "does not match an unrelated revert selector (DIDNotFound = 0x426b82e4)" do
      refute DIDRegistry.did_already_exists?(%{
               "data" => "0x426b82e4",
               "message" => "execution reverted"
             })
    end

    test "does not match transient / non-revert errors" do
      refute DIDRegistry.did_already_exists?(:receipt_timeout)
      refute DIDRegistry.did_already_exists?(%{"message" => "nonce too low"})
      refute DIDRegistry.did_already_exists?(nil)
    end
  end
end
