defmodule Sovra.GuardianTest do
  use Sovra.DataCase, async: true

  alias Sovra.Guardian
  alias Sovra.Auth.MockAuthProvider

  import Sovra.GuardianHelpers

  describe "onboard/2" do
    test "creates holder record and returns recovery public key" do
      {:ok, result} = Guardian.onboard("0xnew_holder", MockAuthProvider.valid_token())

      assert %{recovery_public_key: %{x: x, y: y}} = result
      assert is_binary(x)
      assert is_binary(y)
    end

    test "rejects duplicate sovra_address" do
      {:ok, _} = Guardian.onboard("0xduplicate", MockAuthProvider.valid_token())

      assert {:error, :already_onboarded} =
               Guardian.onboard("0xduplicate", MockAuthProvider.valid_token_2())
    end

    test "returns login session for same google account on different device" do
      {:ok, first} = Guardian.onboard("0xdevice_a", MockAuthProvider.valid_token())
      assert Map.has_key?(first, :recovery_public_key)

      {:ok, second} = Guardian.onboard("0xdevice_b", MockAuthProvider.valid_token())
      assert second.sovra_address == "0xdevice_a"
      assert is_binary(second.session_token)
      refute Map.has_key?(second, :recovery_public_key)
    end

    test "rejects invalid oauth token" do
      assert {:error, :invalid_id_token} = Guardian.onboard("0xholder", "bad-token")
    end
  end

  describe "rotate_recovery_key/1" do
    test "returns new public key and rotation signature" do
      holder = create_test_holder("0xrotate_holder")

      {:ok, result} = Guardian.rotate_recovery_key(holder.sovra_address)

      assert %{new_recovery_public_key: %{x: _, y: _}, rotation_signature: %{r: _, s: _}} = result
    end

    test "old key no longer works after rotation" do
      holder = create_test_holder("0xrotate_old_key")
      old_key_id = holder.recovery_key_id

      {:ok, _} = Guardian.rotate_recovery_key(holder.sovra_address)

      hash = random_hash()
      assert {:error, :key_not_found} = Sovra.Crypto.Key.sign(old_key_id, hash)
    end
  end

  describe "initiate_recovery/2" do
    test "returns signature and sets status to recovery_pending" do
      holder = create_test_holder("0xrecovery_holder")
      {:ok, %{public_key_x: x, public_key_y: y}} = Sovra.Crypto.P256.generate_key_pair()

      {:ok, %{signature: %{r: _, s: _}}} =
        Guardian.initiate_recovery(holder.sovra_address, %{x: x, y: y})

      updated =
        Sovra.Repo.get_by!(Sovra.Guardian.HolderRecord, sovra_address: "0xrecovery_holder")

      assert updated.status == "recovery_pending"
    end
  end
end
