defmodule Sovra.PromEx.RelayerPluginTest do
  # async: false — the reporter owns named ETS tables, and these mutate global
  # app env plus the node-global relayer address memo.
  use ExUnit.Case, async: false

  alias Sovra.Ethereum.Relayer
  alias Sovra.PromEx.RelayerPlugin

  @reporter :relayer_plugin_test_metrics
  @chain_id 999_901
  @balance_event [:sovra, :relayer, :balance]
  @poll_event [:sovra, :relayer, :balance, :poll]
  @key "0x" <> String.duplicate("11", 32)

  setup do
    original = Application.get_env(:sovra, :ethereum, [])

    metrics =
      Enum.flat_map(
        List.wrap(RelayerPlugin.event_metrics(otp_app: :sovra)) ++
          List.wrap(RelayerPlugin.polling_metrics(otp_app: :sovra)),
        & &1.metrics
      )

    start_supervised!(
      {TelemetryMetricsPrometheus.Core, name: @reporter, metrics: metrics, start_async: false}
    )

    Relayer.forget_cached_address()

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.delete_env(:sovra, :relayer_balance_thresholds)
      Relayer.forget_cached_address()
    end)

    :ok
  end

  defp scrape, do: TelemetryMetricsPrometheus.Core.scrape(@reporter)

  defp put_chain(id, opts \\ []) do
    base = [
      relayer_backend: :local,
      rpc_url: "http://127.0.0.1:1",
      chain_id: id,
      chain_name: Keyword.get(opts, :name, "chain-#{id}")
    ]

    base =
      if Keyword.get(opts, :key, true),
        do: Keyword.put(base, :admin_private_key, @key),
        else: base

    # `configured?/0` needs a relayer AND a DID registry, so dropping the
    # registry is what makes a chain known-but-not-configured.
    base =
      if Keyword.get(opts, :configured, true),
        do:
          Keyword.put(base, :did_registry_address, "0x0000000000000000000000000000000000000001"),
        else: base

    Application.put_env(:sovra, :ethereum, base)
  end

  describe "balance metrics" do
    test "exports the balance as a gauge with the exact integer, not a float" do
      :telemetry.execute(
        @balance_event,
        %{wei: 1_500_000_000_000_000_000, timestamp_seconds: 1_700_000_000},
        %{chain_id: @chain_id, chain_name: "stub"}
      )

      text = scrape()

      assert text =~ "# TYPE sovra_relayer_balance_wei gauge"

      assert text =~
               ~s(sovra_relayer_balance_wei{chain_id="#{@chain_id}",chain_name="stub"} 1500000000000000000)

      assert text =~
               ~s(sovra_relayer_balance_last_success_timestamp_seconds{chain_id="#{@chain_id}",chain_name="stub"} 1700000000)
    end

    test "exports poll outcomes as a counter" do
      :telemetry.execute(@poll_event, %{duration_ms: 12}, %{
        chain_id: @chain_id,
        chain_name: "stub",
        result: "rpc_error"
      })

      text = scrape()

      assert text =~ "# TYPE sovra_relayer_balance_poll_total counter"
      assert text =~ ~s(chain_id="#{@chain_id}")
      assert text =~ ~s(result="rpc_error")
    end

    # This is the behaviour every floor alert depends on: a `last_value` gauge
    # has no expiry, so a failed poll keeps serving the previous number. The
    # freshness metric is the only way to notice.
    test "a failed poll leaves the balance and its timestamp untouched" do
      :telemetry.execute(
        @balance_event,
        %{wei: 42, timestamp_seconds: 1_700_000_000},
        %{chain_id: @chain_id, chain_name: "stub"}
      )

      first = scrape()
      assert first =~ ~s(sovra_relayer_balance_wei{chain_id="#{@chain_id}",chain_name="stub"} 42)

      :telemetry.execute(@poll_event, %{duration_ms: 5}, %{
        chain_id: @chain_id,
        chain_name: "stub",
        result: "rpc_error"
      })

      second = scrape()

      assert second =~ ~s(sovra_relayer_balance_wei{chain_id="#{@chain_id}",chain_name="stub"} 42)

      assert second =~
               ~s(sovra_relayer_balance_last_success_timestamp_seconds{chain_id="#{@chain_id}",chain_name="stub"} 1700000000)

      assert second =~ ~s(result="rpc_error")
    end
  end

  describe "config metrics" do
    test "exports the chain's thresholds in wei" do
      put_chain(@chain_id)

      Application.put_env(:sovra, :relayer_balance_thresholds, %{
        @chain_id => %{warning: 50_000_000_000_000_000, critical: 10_000_000_000_000_000}
      })

      RelayerPlugin.execute_config_metrics()
      text = scrape()

      assert text =~
               ~s(sovra_relayer_balance_threshold_wei{chain_id="#{@chain_id}",chain_name="chain-#{@chain_id}",severity="critical"} 10000000000000000)

      assert text =~
               ~s(sovra_relayer_balance_threshold_wei{chain_id="#{@chain_id}",chain_name="chain-#{@chain_id}",severity="warning"} 50000000000000000)
    end

    test "marks a chain without on-chain registries as not configured" do
      put_chain(@chain_id, configured: false, name: "unmonitored")
      RelayerPlugin.execute_config_metrics()

      assert scrape() =~
               ~s(sovra_relayer_chain_info{chain_id="#{@chain_id}",chain_name="unmonitored",configured="false"} 1)
    end

    test "marks a fully configured chain as configured" do
      put_chain(@chain_id, name: "monitored")
      RelayerPlugin.execute_config_metrics()

      assert scrape() =~
               ~s(sovra_relayer_chain_info{chain_id="#{@chain_id}",chain_name="monitored",configured="true"} 1)
    end

    test "falls back to chain-<id> when no chain name is configured" do
      Application.put_env(:sovra, :ethereum,
        relayer_backend: :local,
        admin_private_key: @key,
        rpc_url: "http://127.0.0.1:1",
        chain_id: @chain_id
      )

      RelayerPlugin.execute_config_metrics()

      assert scrape() =~ ~s(chain_name="chain-#{@chain_id}")
    end

    test "exports the relayer address as a label and marks it resolved" do
      put_chain(@chain_id)
      RelayerPlugin.execute_config_metrics()
      text = scrape()

      assert text =~ ~r/sovra_relayer_address_info\{address="0x[0-9a-f]{40}"\} 1/
      assert text =~ "sovra_relayer_address_resolved 1"
    end

    test "reports the address as unresolved when the signer cannot answer" do
      put_chain(@chain_id, key: false)
      Relayer.forget_cached_address()
      RelayerPlugin.execute_config_metrics()
      text = scrape()

      assert text =~ "sovra_relayer_address_resolved 0"
      refute text =~ "sovra_relayer_address_info{"
    end

    test "a chain with no configured floor exports no threshold series" do
      put_chain(@chain_id)
      Application.put_env(:sovra, :relayer_balance_thresholds, %{})
      RelayerPlugin.execute_config_metrics()

      refute scrape() =~ ~s(sovra_relayer_balance_threshold_wei{chain_id="#{@chain_id}")
    end
  end
end
