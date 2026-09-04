defmodule SovraWeb.MetricsServerTest do
  @moduledoc """
  The `/metrics` listener is Bandit serving `PromEx.MetricsServer.Plug`, because
  PromEx's own server is Plug.Cowboy-only and this project has no cowboy. These
  tests pin that the plug behaves under Bandit.
  """
  # async: false — binds a real port and starts the PromEx singleton.
  use ExUnit.Case, async: false

  @port 4602
  @base "http://127.0.0.1:#{@port}"

  setup do
    original = Application.get_env(:sovra, Sovra.PromEx, [])

    Application.put_env(
      :sovra,
      Sovra.PromEx,
      Keyword.merge(original, disabled: false)
    )

    start_supervised!(Sovra.PromEx)

    start_supervised!(
      {Bandit,
       plug: {PromEx.MetricsServer.Plug, %{path: "/metrics", prom_ex_module: Sovra.PromEx}},
       scheme: :http,
       port: @port}
    )

    on_exit(fn -> Application.put_env(:sovra, Sovra.PromEx, original) end)
    :ok
  end

  test "serves the exposition format on the configured path" do
    # Seed one event-driven series; the polled plugins are timer-driven and
    # racing them here would be flaky.
    :telemetry.execute(
      [:sovra, :relayer, :balance],
      %{wei: 7, timestamp_seconds: 1},
      %{chain_id: 1, chain_name: "test"}
    )

    assert %{status: 200, body: body} = Req.get!("#{@base}/metrics", retry: false)
    assert body =~ "# TYPE sovra_relayer_balance_wei gauge"
    assert body =~ ~s(sovra_relayer_balance_wei{chain_id="1",chain_name="test"} 7)
  end

  test "does not answer on any other path" do
    assert %{status: 404} = Req.get!("#{@base}/", retry: false)
  end
end
