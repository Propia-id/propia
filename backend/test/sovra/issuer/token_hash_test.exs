defmodule Sovra.Issuer.TokenHashTest do
  use ExUnit.Case, async: true

  alias Sovra.Issuer.TokenHash

  describe "hash/1" do
    test "produces consistent SHA-256 hex digest" do
      hash1 = TokenHash.hash("test-token")
      hash2 = TokenHash.hash("test-token")
      assert hash1 == hash2
      assert byte_size(hash1) == 64
      assert String.match?(hash1, ~r/^[0-9a-f]{64}$/)
    end

    test "different tokens produce different hashes" do
      hash1 = TokenHash.hash("token-a")
      hash2 = TokenHash.hash("token-b")
      refute hash1 == hash2
    end
  end

  describe "generate_and_hash/1" do
    test "returns {plaintext, hash} tuple" do
      {plaintext, hash} = TokenHash.generate_and_hash(32)
      assert is_binary(plaintext)
      assert is_binary(hash)
      assert byte_size(plaintext) == 64
      assert byte_size(hash) == 64
    end

    test "hash matches re-hashing the plaintext" do
      {plaintext, hash} = TokenHash.generate_and_hash(32)
      assert TokenHash.hash(plaintext) == hash
    end

    test "generates unique tokens each time" do
      {pt1, _} = TokenHash.generate_and_hash(32)
      {pt2, _} = TokenHash.generate_and_hash(32)
      refute pt1 == pt2
    end
  end
end
