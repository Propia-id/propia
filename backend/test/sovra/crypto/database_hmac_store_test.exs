defmodule Sovra.Crypto.DatabaseHmacStoreTest do
  use Sovra.DataCase, async: true

  alias Sovra.Crypto.{DatabaseHmacStore, StoredKey}
  alias Sovra.Repo

  describe "generate_hmac_key/0" do
    test "returns a whsec_-prefixed plaintext and stores only ciphertext" do
      {:ok, %{key_id: key_id, plaintext: plaintext}} = DatabaseHmacStore.generate_hmac_key()

      assert String.starts_with?(plaintext, "whsec_")

      stored = Repo.get_by!(StoredKey, key_id: key_id)
      assert String.starts_with?(stored.private_key, "SKC1")
      refute String.contains?(stored.private_key, plaintext)
    end
  end

  describe "hmac/2" do
    test "matches an HMAC computed with the revealed plaintext" do
      {:ok, %{key_id: key_id, plaintext: plaintext}} = DatabaseHmacStore.generate_hmac_key()

      {:ok, sig} = DatabaseHmacStore.hmac(key_id, "payload")
      assert sig == :crypto.mac(:hmac, :sha256, plaintext, "payload")
    end

    test "still verifies legacy plaintext rows written before encryption" do
      plaintext = "whsec_legacy_secret"

      %{key_id: "webhook-legacy", private_key: plaintext, holder_id: "workspace_webhook"}
      |> StoredKey.changeset()
      |> Repo.insert!()

      {:ok, sig} = DatabaseHmacStore.hmac("webhook-legacy", "payload")
      assert sig == :crypto.mac(:hmac, :sha256, plaintext, "payload")
    end

    test "returns :not_found for an unknown key id" do
      assert {:error, :not_found} = DatabaseHmacStore.hmac("webhook-missing", "payload")
    end
  end

  describe "rotate/1" do
    test "re-encrypts with a fresh secret" do
      {:ok, %{key_id: key_id, plaintext: old_plaintext}} = DatabaseHmacStore.generate_hmac_key()

      {:ok, %{plaintext: new_plaintext}} = DatabaseHmacStore.rotate(key_id)
      assert new_plaintext != old_plaintext

      stored = Repo.get_by!(StoredKey, key_id: key_id)
      assert String.starts_with?(stored.private_key, "SKC1")

      {:ok, sig} = DatabaseHmacStore.hmac(key_id, "payload")
      assert sig == :crypto.mac(:hmac, :sha256, new_plaintext, "payload")
    end
  end
end
