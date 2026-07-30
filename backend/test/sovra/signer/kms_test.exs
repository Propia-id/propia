defmodule Sovra.Signer.KmsTest do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.P256
  alias Sovra.Signer.Kms

  # P-256 group order (for the low-s assertion).
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  test "create_key returns a key id and 32-byte public-key coordinates" do
    assert {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
             Kms.create_key("workspace_1_signing")

    assert is_binary(key_id) and key_id != ""
    assert byte_size(x) == 32
    assert byte_size(y) == 32
  end

  test "sign produces a low-s signature that verifies against the created key" do
    {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} = Kms.create_key("w")
    digest = :crypto.hash(:sha256, "hello sovra")

    assert {:ok, %{r: r, s: s}} = Kms.sign(key_id, digest)
    assert byte_size(r) == 32 and byte_size(s) == 32
    assert P256.verify(digest, %{r: r, s: s}, {x, y})
    assert :binary.decode_unsigned(s) <= div(@n, 2)
  end

  test "sign rejects a digest that is not 32 bytes" do
    assert {:error, :invalid_hash_size} = Kms.sign("stub-00", <<1, 2, 3>>)
  end

  test "schedule_deletion succeeds" do
    {:ok, %{key_id: key_id}} = Kms.create_key("w")
    assert :ok = Kms.schedule_deletion(key_id)
  end

  test "create_key schedules deletion of the minted key when GetPublicKey fails" do
    Process.put(:stub_kms_fail_get_public_key, :throttled)

    assert {:error, :throttled} = Kms.create_key("w")
    assert_received {:stub_kms, :schedule_key_deletion, "stub-p256-" <> _}
  end

  test "create_key rejects a non-string holder_id" do
    assert {:error, :invalid_holder_id} = Kms.create_key(123)
  end

  test "create_key aliases the key under the app namespace" do
    assert {:ok, %{key_id: key_id}} = Kms.create_key("workspace_42_signing")

    assert_received {:stub_kms, :create_alias,
                     {"alias/sovra/test/app/workspace_42_signing", ^key_id}}
  end

  test "create_key sanitizes the holder id in the alias" do
    assert {:ok, %{key_id: key_id}} = Kms.create_key("w s:p.ace")
    assert_received {:stub_kms, :create_alias, {"alias/sovra/test/app/w-s-p-ace", ^key_id}}
  end

  test "create_key falls back to the key id when the holder id is empty" do
    assert {:ok, %{key_id: key_id}} = Kms.create_key("")
    expected = "alias/sovra/test/app/" <> key_id
    assert_received {:stub_kms, :create_alias, {^expected, ^key_id}}
  end

  test "create_key still succeeds when alias creation fails" do
    Process.put(:stub_kms_fail_create_alias, :already_exists)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:ok, %{key_id: _}} = Kms.create_key("w")
      end)

    assert log =~ "Failed to create alias"
  end

  test "create_key does not alias a key it discards" do
    Process.put(:stub_kms_fail_get_public_key, :throttled)

    assert {:error, :throttled} = Kms.create_key("w")
    refute_received {:stub_kms, :create_alias, _}
  end
end
