defmodule Sovra.Ethereum.Relayer.BalanceMonitorTest do
  # async: false — mutates the global :ethereum / :stub_balances env and the
  # node-global relayer address memo.
  use ExUnit.Case, async: false

  alias Sovra.Ethereum.{BalanceReader, Relayer}
  alias Sovra.Ethereum.Relayer.BalanceMonitor

  @chain_id 999_801
  @balance_event [:sovra, :relayer, :balance]
  @poll_event [:sovra, :relayer, :balance, :poll]

  setup do
    original = Application.get_env(:sovra, :ethereum, [])
    put_chain(@chain_id)
    Relayer.forget_cached_address()

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.delete_env(:sovra, :stub_balances)
      Application.delete_env(:sovra, :relayer_address_ttl_ms)
      Relayer.forget_cached_address()
    end)

    :ok
  end

  defp put_chain(chain_id, opts \\ []) do
    Application.put_env(
      :sovra,
      :ethereum,
      relayer_backend: :local,
      admin_private_key: Keyword.get(opts, :key, "0x" <> String.duplicate("11", 32)),
      rpc_url: "http://127.0.0.1:1",
      chain_id: chain_id,
      chain_name: Keyword.get(opts, :name, "chain-#{chain_id}"),
      did_registry_address: "0x0000000000000000000000000000000000000001"
    )
  end

  defp attach(events) do
    :telemetry_test.attach_event_handlers(self(), events)
    on_exit(fn -> :telemetry.detach({:telemetry_test, events, self()}) end)
  end

  defp start_monitor(opts \\ []) do
    defaults = [enabled: true, reader: BalanceReader.Stub, chain_timeout_ms: 500]
    start_supervised!({BalanceMonitor, Keyword.merge(defaults, opts)})
  end

  defp stub_balances(map), do: Application.put_env(:sovra, :stub_balances, map)

  describe "polling" do
    test "emits a balance and an ok poll for the chain" do
      stub_balances(%{@chain_id => {:ok, 123}})
      attach([@balance_event, @poll_event])
      start_monitor()

      assert %{@chain_id => {:ok, 123}} = BalanceMonitor.poll_now()

      assert_receive {@balance_event, _, %{wei: 123, timestamp_seconds: ts},
                      %{chain_id: @chain_id, chain_name: _}}

      assert is_integer(ts)

      assert_receive {@poll_event, _, %{duration_ms: _},
                      %{chain_id: @chain_id, chain_name: _, result: "ok"}}
    end

    test "a failing read reports a poll outcome and no balance" do
      stub_balances(%{@chain_id => {:error, :econnrefused}})
      attach([@balance_event, @poll_event])
      start_monitor()

      assert %{@chain_id => {:error, :econnrefused}} = BalanceMonitor.poll_now()

      assert_receive {@poll_event, _, _,
                      %{chain_id: @chain_id, chain_name: _, result: "rpc_error"}}

      refute_receive {@balance_event, _, _, %{chain_id: @chain_id}}
    end

    test "a hung chain times out and is labelled" do
      stub_balances(%{@chain_id => {:sleep, 5_000}})
      attach([@balance_event, @poll_event])
      start_monitor(chain_timeout_ms: 100)

      assert %{@chain_id => {:error, :timeout}} = BalanceMonitor.poll_now()

      assert_receive {@poll_event, _, _, %{chain_id: @chain_id, chain_name: _, result: "timeout"}}

      refute_receive {@balance_event, _, _, %{chain_id: @chain_id}}
    end

    test "a raising reader is contained rather than taking the monitor down" do
      stub_balances(%{@chain_id => {:raise, "boom"}})
      attach([@poll_event])
      pid = start_monitor()

      assert %{@chain_id => {:error, {:exception, "boom"}}} = BalanceMonitor.poll_now()

      assert_receive {@poll_event, _, _,
                      %{chain_id: @chain_id, chain_name: _, result: "rpc_error"}}

      # Still responsive after the failure.
      assert is_map(BalanceMonitor.poll_now())
      assert _ = :sys.get_state(pid)
    end

    test "labels an unconfigured chain distinctly from an RPC failure" do
      stub_balances(%{@chain_id => {:error, :chain_rpc_not_configured}})
      attach([@poll_event])
      start_monitor()

      BalanceMonitor.poll_now()

      assert_receive {@poll_event, _, _,
                      %{chain_id: @chain_id, chain_name: _, result: "unconfigured"}}
    end

    test "labels a decode failure distinctly from an RPC failure" do
      stub_balances(%{@chain_id => {:error, :invalid_uint_response}})
      attach([@poll_event])
      start_monitor()

      BalanceMonitor.poll_now()

      assert_receive {@poll_event, _, _,
                      %{chain_id: @chain_id, chain_name: _, result: "decode_error"}}
    end
  end

  describe "signer unavailable" do
    test "reports a failure per chain, emits no balance, and stays alive" do
      Application.put_env(:sovra, :ethereum, relayer_backend: :local, chain_id: @chain_id)
      Relayer.forget_cached_address()
      attach([@balance_event, @poll_event])
      pid = start_monitor()

      assert %{} == BalanceMonitor.poll_now()

      assert_receive {@poll_event, _, _,
                      %{chain_id: @chain_id, chain_name: _, result: "signer_unavailable"}}

      refute_receive {@balance_event, _, _, _}

      assert _ = :sys.get_state(pid)
    end
  end

  describe "key rotation" do
    # signer.deploy swaps RELAYER_KMS_KEY_ID and restarts the SIGNER; the API
    # nodes keep running, so only the TTL makes monitoring follow the new key.
    test "a running monitor follows a rotated key once the TTL expires" do
      attach([@balance_event])
      start_monitor()

      BalanceMonitor.poll_now()
      assert_receive {@balance_event, _, _, %{chain_id: @chain_id}}
      {:ok, before} = Relayer.cached_address()

      # Rotate underneath the running process.
      put_chain(@chain_id, key: "0x" <> String.duplicate("22", 32))

      # Still the old address while the memo is live...
      assert {:ok, ^before} = Relayer.cached_address()

      # ...and the new one once it expires, with no restart.
      Application.put_env(:sovra, :relayer_address_ttl_ms, 0)

      assert {:ok, rotated} = Relayer.cached_address()
      refute rotated == before

      BalanceMonitor.poll_now()
      assert_receive {@balance_event, _, _, %{chain_id: @chain_id}}
    end
  end

  describe "lifecycle" do
    test "does not start when disabled" do
      # init/1 returns :ignore, which the supervisor records as an undefined pid
      # — the child is listed but no process exists.
      assert {:ok, :undefined} = start_supervised({BalanceMonitor, enabled: false})
      refute Process.whereis(BalanceMonitor)
    end

    test "init/1 performs no I/O — a raising reader only fails on the first poll" do
      stub_balances(%{@chain_id => {:raise, "boom"}})
      attach([@balance_event])

      # Starting must succeed even though every read would raise.
      pid = start_monitor()
      assert _ = :sys.get_state(pid)
      refute_receive {@balance_event, _, _, _}
    end

    test "handles an empty chain inventory" do
      Application.put_env(:sovra, :ethereum,
        relayer_backend: :local,
        admin_private_key: "0x" <> String.duplicate("11", 32)
      )

      Relayer.forget_cached_address()
      start_monitor()
      assert %{} == BalanceMonitor.poll_now()
    end
  end
end
