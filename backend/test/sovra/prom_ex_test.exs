defmodule Sovra.PromExTest do
  # async: false — PromEx is a singleton and its reporter owns named ETS tables.
  # No alias: `PromEx` must resolve to the library module, whose
  # `get_metrics/1` takes ours.
  use SovraWeb.ConnCase, async: false

  alias Sovra.Ethereum.{BalanceReader, Relayer}
  alias Sovra.Ethereum.Relayer.BalanceMonitor

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

  test "drops the channel and socket groups this app does not use" do
    text = scrape()

    refute text =~ "phoenix_channel"
    refute text =~ "phoenix_socket"
  end
end
