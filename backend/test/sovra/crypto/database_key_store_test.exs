defmodule Sovra.Crypto.DatabaseKeyStoreTest do
  use Sovra.DataCase, async: true

  alias Sovra.Crypto.{DatabaseKeyStore, P256, StoredKey}
  alias Sovra.Repo

  describe "generate_key/1" do
    test "returns key_id and public key coordinates" do
      {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
        DatabaseKeyStore.generate_key("holder-1")

      assert is_binary(key_id)

      assert String.match?(
               key_id,
               ~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
             )

      assert byte_size(x) == 32
      assert byte_size(y) == 32
    end

    test "persists key in database" do
      {:ok, %{key_id: key_id}} = DatabaseKeyStore.generate_key("holder-2")

      stored = Repo.get_by!(StoredKey, key_id: key_id)
      assert byte_size(stored.private_key) == 32
    end
  end

  describe "sign/2" do
    test "signs and produces a verifiable signature" do
      {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
        DatabaseKeyStore.generate_key("holder-sign")

      hash = :crypto.strong_rand_bytes(32)
      {:ok, %{r: r, s: s}} = DatabaseKeyStore.sign(key_id, hash)

      assert byte_size(r) == 32
      assert byte_size(s) == 32
      assert P256.verify(hash, %{r: r, s: s}, {x, y})
    end

    test "returns error for unknown key_id" do
      hash = :crypto.strong_rand_bytes(32)
      assert {:error, :key_not_found} = DatabaseKeyStore.sign("nonexistent-key", hash)
    end
  end

  describe "delete_key/1" do
    test "deletes key and subsequent sign fails" do
      {:ok, %{key_id: key_id}} = DatabaseKeyStore.generate_key("holder-delete")
      hash = :crypto.strong_rand_bytes(32)

      assert {:ok, _} = DatabaseKeyStore.sign(key_id, hash)
      assert :ok = DatabaseKeyStore.delete_key(key_id)
      assert {:error, :key_not_found} = DatabaseKeyStore.sign(key_id, hash)
    end

    test "deleting a nonexistent key is a no-op" do
      assert :ok = DatabaseKeyStore.delete_key("nonexistent-key")
    end
  end
end
