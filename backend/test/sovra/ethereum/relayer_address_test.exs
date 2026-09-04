defmodule Sovra.Ethereum.RelayerAddressTest do
  # async: false — the memo lives in :persistent_term, which is node-global.
  use ExUnit.Case, async: false

  alias Sovra.Ethereum.Relayer

  @key_a "0x" <> String.duplicate("11", 32)
  @key_b "0x" <> String.duplicate("22", 32)

  setup do
    original = Application.get_env(:sovra, :ethereum, [])
    Relayer.forget_cached_address()

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.delete_env(:sovra, :relayer_address_ttl_ms)
      Relayer.forget_cached_address()
    end)

    :ok
  end

  defp put_key(hex) do
    Application.put_env(:sovra, :ethereum,
      relayer_backend: :local,
      admin_private_key: hex
    )
  end

  defp address_of(hex) do
    {:ok, [checksummed]} = Ethers.Signer.Local.accounts(private_key: hex)
    {:ok, raw} = Base.decode16(String.replace_prefix(checksummed, "0x", ""), case: :mixed)
    raw
  end

  describe "address/0" do
    test "derives the address from the configured signer, as 20 raw bytes" do
      put_key(@key_a)
      assert {:ok, address} = Relayer.address()
      assert byte_size(address) == 20
      assert address == address_of(@key_a)
    end

    test "reflects a rotated key immediately — the submit path stays uncached" do
      put_key(@key_a)
      assert {:ok, first} = Relayer.address()

      put_key(@key_b)
      assert {:ok, second} = Relayer.address()

      refute first == second
      assert second == address_of(@key_b)
    end

    test "reports a missing key rather than raising" do
      Application.put_env(:sovra, :ethereum, relayer_backend: :local)
      assert {:error, :no_private_key} = Relayer.address()
    end

    test "hex/1 renders the label form the metrics use" do
      put_key(@key_a)
      assert {:ok, address} = Relayer.address()
      assert Relayer.hex(address) =~ ~r/^0x[0-9a-f]{40}$/
    end
  end

  describe "cached_address/0" do
    test "memoizes, and forget_cached_address/0 clears the memo" do
      put_key(@key_a)
      assert {:ok, first} = Relayer.cached_address()

      # Rotating the key alone must NOT change the memoized answer.
      put_key(@key_b)
      assert {:ok, ^first} = Relayer.cached_address()

      assert :ok = Relayer.forget_cached_address()
      assert {:ok, second} = Relayer.cached_address()
      assert second == address_of(@key_b)
    end

    # The rotation this bounds: `signer.deploy` swaps RELAYER_KMS_KEY_ID and
    # restarts the signer, but not the API nodes.
    test "re-resolves once the TTL has expired, picking up a rotated key" do
      put_key(@key_a)
      assert {:ok, first} = Relayer.cached_address()

      # The age is compared at read time, so a shortened TTL applies to what is
      # already memoized.
      Application.put_env(:sovra, :relayer_address_ttl_ms, 0)
      put_key(@key_b)

      assert {:ok, second} = Relayer.cached_address()
      refute second == first
      assert second == address_of(@key_b)
    end

    test "does not cache errors, so a signer down at boot is retried" do
      Application.put_env(:sovra, :ethereum, relayer_backend: :local)
      assert {:error, :no_private_key} = Relayer.cached_address()

      put_key(@key_a)
      assert {:ok, address} = Relayer.cached_address()
      assert address == address_of(@key_a)
    end
  end
end
