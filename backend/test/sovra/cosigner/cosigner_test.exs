defmodule Sovra.CosignerTest do
  use Sovra.DataCase, async: true

  alias Sovra.Cosigner
  alias Sovra.Auth.MockAuthProvider

  import Sovra.CosignerHelpers

  describe "onboard/2" do
    test "creates holder record and returns server public key" do
      {:ok, result} = Cosigner.onboard("0xnew_holder", MockAuthProvider.valid_token())

      assert %{server_public_key: %{x: x, y: y}} = result
      assert is_binary(x)
      assert is_binary(y)
    end

    test "rejects duplicate sovra_address" do
      {:ok, _} = Cosigner.onboard("0xduplicate", MockAuthProvider.valid_token())

      assert {:error, :already_onboarded} =
               Cosigner.onboard("0xduplicate", MockAuthProvider.valid_token())
    end

    test "rejects invalid oauth token" do
      assert {:error, :invalid_id_token} = Cosigner.onboard("0xholder", "bad-token")
    end
  end

  describe "cosign/2" do
    test "signs hash for active holder" do
      holder = create_test_holder("0xcosign_holder")
      hash = random_hash()

      {:ok, %{r: r, s: s}} = Cosigner.cosign(holder.sovra_address, hash)

      assert byte_size(r) == 32
      assert byte_size(s) == 32
    end

    test "rejects unknown holder" do
      assert {:error, :holder_not_found} = Cosigner.cosign("0xunknown", random_hash())
    end

    test "rejects invalid hash size" do
      create_test_holder("0xinvalid_hash")

      assert {:error, :invalid_hash_size} = Cosigner.cosign("0xinvalid_hash", <<1, 2, 3>>)
    end

    test "signature is verifiable with stored public key" do
      holder = create_test_holder("0xverifiable")
      hash = random_hash()

      {:ok, sig} = Cosigner.cosign(holder.sovra_address, hash)

      assert Sovra.Crypto.P256.verify(
               hash,
               sig,
               {holder.server_public_key_x, holder.server_public_key_y}
             )
    end
  end

  describe "rotate_server_key/1" do
    test "returns new public key and rotation signature" do
      holder = create_test_holder("0xrotate_holder")

      {:ok, result} = Cosigner.rotate_server_key(holder.sovra_address)

      assert %{new_server_public_key: %{x: _, y: _}, rotation_signature: %{r: _, s: _}} = result
    end

    test "old key no longer works after rotation" do
      holder = create_test_holder("0xrotate_old_key")
      old_key_id = holder.server_key_id

      {:ok, _} = Cosigner.rotate_server_key(holder.sovra_address)

      hash = random_hash()
      assert {:error, :key_not_found} = Sovra.Crypto.Key.sign(old_key_id, hash)
    end
  end

  describe "initiate_recovery/2" do
    test "returns signature and sets status to recovery_pending" do
      holder = create_test_holder("0xrecovery_holder")
      {:ok, %{public_key_x: x, public_key_y: y}} = Sovra.Crypto.P256.generate_key_pair()

      {:ok, %{signature: %{r: _, s: _}}} =
        Cosigner.initiate_recovery(holder.sovra_address, %{x: x, y: y})

      updated =
        Sovra.Repo.get_by!(Sovra.Cosigner.HolderRecord, sovra_address: "0xrecovery_holder")

      assert updated.status == "recovery_pending"
    end
  end
end
