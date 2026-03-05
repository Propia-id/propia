defmodule Sovra.Crypto.SoftwareKeyStoreTest do
  use ExUnit.Case, async: false

  alias Sovra.Crypto.SoftwareKeyStore

  describe "generate_key/1" do
    test "returns key_id and public key coordinates" do
      {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
        SoftwareKeyStore.generate_key("holder-1")

      assert is_binary(key_id)

      assert String.match?(
               key_id,
               ~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
             )

      assert byte_size(x) == 32
      assert byte_size(y) == 32
    end
  end

  describe "sign/2" do
    test "signs with a valid key" do
      {:ok, %{key_id: key_id}} = SoftwareKeyStore.generate_key("holder-sign")
      hash = :crypto.strong_rand_bytes(32)

      {:ok, %{r: r, s: s}} = SoftwareKeyStore.sign(key_id, hash)

      assert byte_size(r) == 32
      assert byte_size(s) == 32
    end

    test "returns error for unknown key_id" do
      hash = :crypto.strong_rand_bytes(32)

      assert {:error, :key_not_found} = SoftwareKeyStore.sign("nonexistent-key", hash)
    end
  end

  describe "delete_key/1" do
    test "deletes key and subsequent sign fails" do
      {:ok, %{key_id: key_id}} = SoftwareKeyStore.generate_key("holder-delete")
      hash = :crypto.strong_rand_bytes(32)

      assert {:ok, _} = SoftwareKeyStore.sign(key_id, hash)

      assert :ok = SoftwareKeyStore.delete_key(key_id)
      assert {:error, :key_not_found} = SoftwareKeyStore.sign(key_id, hash)
    end
  end
end
