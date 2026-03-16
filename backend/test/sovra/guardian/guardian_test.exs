defmodule Sovra.GuardianTest do
  use Sovra.DataCase, async: true

  alias Sovra.Guardian
  alias Sovra.Auth.MockAuthProvider

  import Sovra.GuardianHelpers

  describe "onboard/2" do
    test "creates holder record and returns recovery public key" do
      {:ok, result} = Guardian.onboard(test_address("new_holder"), MockAuthProvider.valid_token())

      assert %{recovery_public_key: %{x: x, y: y}} = result
      assert is_binary(x)
      assert is_binary(y)
    end

    test "rejects duplicate sovra_address" do
      {:ok, _} = Guardian.onboard(test_address("duplicate"), MockAuthProvider.valid_token())

      assert {:error, :already_onboarded} =
               Guardian.onboard(test_address("duplicate"), MockAuthProvider.valid_token_2())
    end

    test "returns login session for same google account on different device" do
      {:ok, first} = Guardian.onboard(test_address("device_a"), MockAuthProvider.valid_token())
      assert Map.has_key?(first, :recovery_public_key)

      {:ok, second} = Guardian.onboard(test_address("device_b"), MockAuthProvider.valid_token())
      assert second.sovra_address == test_address("device_a")
      assert is_binary(second.session_token)
      refute Map.has_key?(second, :recovery_public_key)
    end

    test "rejects invalid oauth token" do
      assert {:error, :invalid_id_token} = Guardian.onboard(test_address("holder"), "bad-token")
    end
  end

  describe "rotate_recovery_key/1" do
    test "returns new public key and rotation signature" do
      holder = create_test_holder(test_address("rotate_holder"))

      {:ok, result} = Guardian.rotate_recovery_key(holder.sovra_address)

      assert %{new_recovery_public_key: %{x: _, y: _}, rotation_signature: %{r: _, s: _}} = result
    end

    test "old key is preserved after rotation (pending on-chain confirmation)" do
      holder = create_test_holder(test_address("rotate_old_key"))
      old_key_id = holder.recovery_key_id

      {:ok, _} = Guardian.rotate_recovery_key(holder.sovra_address)

      # Old key should still exist (not deleted until confirm_rotation)
      hash = random_hash()
      assert {:ok, _sig} = Sovra.Crypto.Key.sign(old_key_id, hash)
    end

    test "confirm_rotation deletes the previous key" do
      holder = create_test_holder(test_address("rotate_confirm"))

      old_key_id = holder.recovery_key_id
      {:ok, _} = Guardian.rotate_recovery_key(holder.sovra_address)

      :ok = Guardian.confirm_rotation(holder.sovra_address)

      hash = random_hash()
      assert {:error, :key_not_found} = Sovra.Crypto.Key.sign(old_key_id, hash)
    end
  end

  describe "initiate_recovery/2" do
    test "returns signature and sets status to recovery_pending" do
      addr = test_address("recovery_holder")
      holder = create_test_holder(addr)
      message_hash = random_hash()

      {:ok, %{signature: %{r: _, s: _}}} =
        Guardian.initiate_recovery(holder.sovra_address, message_hash)

      updated =
        Sovra.Repo.get_by!(Sovra.Guardian.HolderRecord, sovra_address: addr)

      assert updated.status == "recovery_pending"
    end
  end

  describe "finalize_recovery/2" do
    test "returns signature and sets status back to active" do
      addr = test_address("finalize_holder")
      holder = create_test_holder(addr)

      {:ok, _} = Guardian.initiate_recovery(holder.sovra_address, random_hash())

      {:ok, %{signature: %{r: r, s: s}}} =
        Guardian.finalize_recovery(holder.sovra_address, random_hash())

      assert is_binary(r)
      assert is_binary(s)

      updated =
        Sovra.Repo.get_by!(Sovra.Guardian.HolderRecord, sovra_address: addr)

      assert updated.status == "active"
    end

    test "rejects non-recovery_pending holders" do
      holder = create_test_holder(test_address("finalize_active"))

      assert {:error, :not_in_recovery} =
               Guardian.finalize_recovery(holder.sovra_address, random_hash())
    end

    test "rejects unknown holders" do
      assert {:error, :holder_not_found} = Guardian.finalize_recovery("0xunknown", random_hash())
    end
  end
end
