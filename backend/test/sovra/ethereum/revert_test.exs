defmodule Sovra.Ethereum.RevertTest do
  use ExUnit.Case, async: true

  alias Sovra.Ethereum.Revert

  describe "selector/1" do
    test "is the first four bytes of keccak256 of the signature" do
      assert Revert.selector("DIDAlreadyExists()") == "0x338c38da"
    end
  end

  describe "matches?/2" do
    @selector Revert.selector("AlreadyRegistered()")

    test "finds the selector in the error's data" do
      assert Revert.matches?(%{"code" => 3, "data" => @selector}, @selector)
    end

    test "finds the selector folded into the message" do
      assert Revert.matches?(%{"message" => "execution reverted: " <> @selector}, @selector)
      assert Revert.matches?("execution reverted: " <> @selector, @selector)
    end

    test "does not match another error or a non-revert failure" do
      other = Revert.selector("IssuerNotRegistered()")

      refute Revert.matches?(%{"data" => other}, @selector)
      refute Revert.matches?(:receipt_timeout, @selector)
      refute Revert.matches?(%{"data" => nil}, @selector)
    end
  end
end
