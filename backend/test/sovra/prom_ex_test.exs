defmodule Sovra.PromExTest do
  # async: false — PromEx is a singleton and its reporter owns named ETS tables.
  # No alias: `PromEx` must resolve to the library module, whose
  # `get_metrics/1` takes ours.
  use SovraWeb.ConnCase, async: false

  alias Sovra.BuildInfo
  alias Sovra.Ethereum.{BalanceReader, Relayer}
  alias Sovra.Ethereum.Relayer.BalanceMonitor
  alias Sovra.Health
  alias Sovra.PromEx.BuildPlugin

  setup do
    original = Application.get_env(:sovra, Sovra.PromEx, [])

    Application.put_env(
      :sovra,
      Sovra.PromEx,
      Keyword.merge(original, disabled: false)
    )

    start_supervised!(Sovra.PromEx)

    on_exit(fn ->
      Application.put_env(:sovra, Sovra.PromEx, original)
    end)

    :ok
  end

  defp scrape, do: PromEx.get_metrics(Sovra.PromEx)

  test "exposes Phoenix, Ecto, BEAM and relayer metric families", %{conn: conn} do
    # Phoenix and Ecto HTTP/query families only materialise once an event has
    # actually fired, so drive one real request and one real query.
    assert conn |> get(~p"/health") |> json_response(200)
    Sovra.Repo.all(Sovra.Accounts.User)

    :telemetry.execute(
      [:sovra, :relayer, :balance],
      %{wei: 1, timestamp_seconds: 1},
      %{chain_id: 1, chain_name: "test"}
    )

    text = scrape()

    # Only event-driven families are asserted. The BEAM and Application plugins
    # are timer-driven, so whether they have emitted yet is a race.
    assert text =~ "sovra_prom_ex_ecto_repo_query_queue_time_milliseconds"
    assert text =~ "sovra_prom_ex_phoenix_http_requests_total"
    assert text =~ "sovra_relayer_balance_wei"
  end

  # The seam between the two halves: the poller's telemetry has to land on the
  # plugin's gauges under the names the alert rules and dashboard hard-code.
  test "a real poll cycle lands on the exported gauges" do
    chain_id = 999_501
    original = Application.get_env(:sovra, :ethereum, [])

    Application.put_env(:sovra, :ethereum,
      relayer_backend: :local,
      admin_private_key: "0x" <> String.duplicate("11", 32),
      rpc_url: "http://127.0.0.1:1",
      chain_id: chain_id,
      chain_name: "integration-chain",
      did_registry_address: "0x0000000000000000000000000000000000000001"
    )

    Application.put_env(:sovra, :stub_balances, %{
      chain_id => {:ok, 4_200_000_000_000_000_000}
    })

    Relayer.forget_cached_address()

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.delete_env(:sovra, :stub_balances)
      Relayer.forget_cached_address()
    end)

    start_supervised!({BalanceMonitor, enabled: true, reader: BalanceReader.Stub})

    assert %{^chain_id => {:ok, _}} = BalanceMonitor.poll_now()

    text = scrape()

    assert text =~
             ~s(sovra_relayer_balance_wei{chain_id="#{chain_id}",chain_name="integration-chain"} 4200000000000000000)

    assert text =~
             ~s(sovra_relayer_balance_poll_total{chain_id="#{chain_id}",chain_name="integration-chain",result="ok"} 1)

    assert text =~
             ~s(sovra_relayer_balance_last_success_timestamp_seconds{chain_id="#{chain_id}",chain_name="integration-chain"})
  end

  # Same seam for readiness: the alert rules in
  # `infra/.../alerting/10-rules.yaml.j2` hard-code these names, and nothing else
  # would notice a rename until an outage failed to page.
  test "a real health cycle lands on the exported gauges" do
    chain_id = 999_502
    original = Application.get_env(:sovra, :ethereum, [])
    original_signer = Application.get_env(:sovra, :signer, [])

    Application.put_env(:sovra, :ethereum,
      chain_id: chain_id,
      chain_name: "health-chain",
      rpc_url: "http://rpc.test"
    )

    Application.put_env(:sovra, :stub_chain_ids, %{"http://rpc.test" => {:ok, chain_id}})
    # No signer service, so both signer checks are `skipped`. The suite's
    # `Req.Test` stub is owned by the test process, which the monitor's tasks are
    # not in the ownership chain of; `Sovra.HealthTest` covers those paths with a
    # bare function plug instead.
    Application.put_env(:sovra, :signer, [])

    on_exit(fn ->
      Application.put_env(:sovra, :ethereum, original)
      Application.put_env(:sovra, :signer, original_signer)
      Application.delete_env(:sovra, :stub_chain_ids)
    end)

    start_supervised!({Health, enabled: true, interval_ms: 60_000})
    assert %{status: :ok} = Health.check_now()

    text = scrape()

    assert text =~
             ~s(sovra_health_dependency_up{chain_id="",chain_name="",dependency="database"} 1)

    assert text =~
             ~s(sovra_health_dependency_up{chain_id="#{chain_id}",chain_name="health-chain",dependency="rpc"} 1)

    assert text =~ "sovra_health_ready 1"
    assert text =~ "sovra_health_last_check_timestamp_seconds"
    assert text =~ "sovra_health_check_duration_milliseconds_count"
  end

  # The names the version dashboard and the drift rules hard-code.
  test "the build stamp lands on the exported info series" do
    BuildPlugin.execute_build_metrics()

    text = scrape()

    assert text =~
             ~s(sovra_build_info{ref="#{BuildInfo.ref()}",revision="#{BuildInfo.revision()}",version="#{BuildInfo.version()}"} 1)

    # Exactly the stamp, or no line at all — never 0, which would read as 1970.
    assert text
           |> String.split("\n")
           |> Enum.filter(&String.starts_with?(&1, "sovra_build_timestamp_seconds ")) ==
             Enum.map(
               List.wrap(BuildInfo.built_at_unix()),
               &"sovra_build_timestamp_seconds #{&1}"
             )
  end

  test "drops the channel and socket groups this app does not use" do
    text = scrape()

    refute text =~ "phoenix_channel"
    refute text =~ "phoenix_socket"
  end
end
