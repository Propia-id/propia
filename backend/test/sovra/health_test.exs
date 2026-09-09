defmodule Sovra.HealthTest do
  # async: false — swaps global config and uses a named singleton. It also puts
  # the sandbox in shared mode, which is what lets the monitor process (and the
  # tasks it spawns) reach the same connection.
  use Sovra.DataCase, async: false

  alias Sovra.Health

  setup do
    prev = %{
      ethereum: Application.get_env(:sovra, :ethereum),
      signer: Application.get_env(:sovra, :signer),
      stub_chain_ids: Application.get_env(:sovra, :stub_chain_ids)
    }

    # No chain and no signer service: the baseline every test adds one back to.
    Application.put_env(:sovra, :ethereum, [])
    Application.put_env(:sovra, :signer, [])

    on_exit(fn -> Enum.each(prev, fn {key, value} -> restore(key, value) end) end)

    :ok
  end

  test "reports :unavailable when the monitor is not running" do
    assert Health.snapshot() == :unavailable
  end

  # The property the whole ETS design exists for: the endpoint reads the snapshot
  # while the monitor is busy inside its first cycle, and gets an answer.
  test "reads :starting while the first cycle is still running" do
    put_chain(31_337, "http://slow.test")
    stub_chain_ids(%{"http://slow.test" => fn -> Process.sleep(500) && {:ok, 31_337} end})
    start_monitor()

    assert %{status: :starting, checked_at: nil, checks: %{}} = Health.snapshot()
  end

  test "all dependencies healthy → :ok" do
    start_monitor()

    assert %{status: :ok, checks: checks} = Health.check_now()
    assert %{status: :ok} = checks.database
    # No signer service configured, so there is nothing to reach.
    assert %{status: :skipped} = checks.signer
    assert %{status: :skipped} = checks.signer_kms
    refute Map.has_key?(checks, :rpc)
  end

  test "a healthy chain reports ok under its chain id" do
    put_chain(31_337, "http://rpc.test")
    stub_chain_ids(%{"http://rpc.test" => {:ok, 31_337}})
    start_monitor()

    assert %{status: :ok, checks: %{rpc: %{31_337 => entry}}} = Health.check_now()
    assert %{status: :ok, chain_name: "chain-31337"} = entry
  end

  test "an unreachable chain fails the cycle" do
    put_chain(31_337, "http://rpc.test")
    stub_chain_ids(%{"http://rpc.test" => {:error, :chain_id_unreachable}})
    start_monitor()

    assert %{status: :error, checks: %{rpc: %{31_337 => entry}}} = Health.check_now()
    assert %{status: :error, error: :unreachable} = entry
  end

  # An endpoint answering for the wrong chain is worse than one not answering:
  # every transaction built against it would target the wrong network.
  test "a chain whose RPC reports a different id fails the cycle" do
    put_chain(31_337, "http://rpc.test")
    stub_chain_ids(%{"http://rpc.test" => {:ok, 1}})
    start_monitor()

    assert %{status: :error, checks: %{rpc: %{31_337 => %{error: :chain_id_mismatch}}}} =
             Health.check_now()
  end

  test "a configured chain with no rpc_url reports unconfigured" do
    put_chain(31_337, nil)
    start_monitor()

    assert %{status: :error, checks: %{rpc: %{31_337 => %{error: :unconfigured}}}} =
             Health.check_now()
  end

  test "an unreachable signer fails the cycle" do
    put_signer(fn conn -> Req.Test.transport_error(conn, :econnrefused) end)
    start_monitor()

    assert %{status: :error, checks: checks} = Health.check_now()
    assert %{status: :error, error: :unreachable} = checks.signer
    assert %{status: :error, error: :unreachable} = checks.signer_kms
  end

  # The case the two checks exist to tell apart: the signer answers, its token is
  # accepted, and the relayer address comes back from its memo — while KMS itself
  # is gone. `check_signer/0` alone would call this healthy.
  test "a signer whose KMS is down fails the cycle, but the signer check passes" do
    put_signer(&signer_plug(&1, kms: "error"))
    start_monitor()

    assert %{status: :error, checks: checks} = Health.check_now()
    assert %{status: :ok} = checks.signer
    assert %{status: :error, error: :error} = checks.signer_kms
  end

  test "a rotated SIGNER_TOKEN surfaces as auth_error, not as unreachable" do
    put_signer(fn
      %{request_path: "/ready"} = conn -> signer_plug(conn, kms: "ok")
      conn -> conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{error: "unauthorized"})
    end)

    start_monitor()

    assert %{status: :error, checks: checks} = Health.check_now()
    assert %{status: :error, error: :auth_error} = checks.signer
    assert %{status: :ok} = checks.signer_kms
  end

  # The rollout window: `deploy.services` deploys the API before the signer, so
  # for minutes the signer runs a router with no /ready, which authenticates
  # BEFORE it dispatches — an unauthenticated probe there gets 401, and only an
  # authenticated one reaches the 404 catch-all. Reading that as "KMS is down"
  # would 503 every API node, and page, for the length of the rollout.
  test "a signer with no readiness route reads as skipped, not as an error" do
    put_signer(&legacy_signer_plug/1)
    start_monitor()

    assert %{status: :ok, checks: checks} = Health.check_now()
    assert %{status: :skipped} = checks.signer_kms
  end

  test "a signer that 404s the readiness route outright also reads as skipped" do
    put_signer(fn
      %{request_path: "/ready"} = conn ->
        conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{error: "not_found"})

      conn ->
        signer_plug(conn, kms: "ok")
    end)

    start_monitor()

    assert %{status: :ok, checks: checks} = Health.check_now()
    assert %{status: :skipped} = checks.signer_kms
  end

  # The retry that tells a route-less signer apart from a bad token must not
  # become a loop when the token is the problem: 401 unauthenticated, 401
  # authenticated, then a verdict.
  test "a signer that rejects the token on both attempts reports auth_error once" do
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    put_signer(fn conn ->
      if conn.request_path == "/ready", do: Agent.update(counter, &(&1 + 1))
      conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{error: "unauthorized"})
    end)

    start_monitor()
    assert %{status: :error, checks: checks} = Health.check_now()
    assert %{status: :error, error: :auth_error} = checks.signer_kms

    # Count one known cycle, now that the boot cycle has drained.
    Agent.update(counter, fn _ -> 0 end)
    Health.check_now()
    assert Agent.get(counter, & &1) == 2
  end

  test "a signer that answers 200 with a body we do not recognise is an error" do
    put_signer(fn
      %{request_path: "/ready"} = conn -> Req.Test.json(conn, %{status: "ok"})
      conn -> signer_plug(conn, kms: "ok")
    end)

    start_monitor()

    assert %{status: :error, checks: %{signer_kms: %{error: :error}}} = Health.check_now()
  end

  test "the monitor survives a check that raises" do
    put_chain(31_337, "http://rpc.test")
    stub_chain_ids(%{"http://rpc.test" => fn -> raise "probe blew up" end})
    pid = start_monitor()

    assert %{status: :error, checks: %{rpc: %{31_337 => %{error: :error}}}} = Health.check_now()
    assert Process.alive?(pid)
  end

  describe "label/1" do
    test "maps every reason onto the closed set the probe may expose" do
      assert Health.label(:timeout) == :timeout
      assert Health.label(:db_standby) == :db_standby
      assert Health.label(:chain_id_unreachable) == :unreachable
      assert Health.label(:invalid_chain_id) == :rpc_error
      assert Health.label(:chain_rpc_not_configured) == :unconfigured
      assert Health.label(:signer_token_missing) == :unconfigured
      assert Health.label({:signer_unreachable, :econnrefused}) == :unreachable
      assert Health.label({:signer_error, 401, %{}}) == :auth_error
      assert Health.label(%DBConnection.ConnectionError{message: "x"}) == :db_error
      assert Health.label(%Postgrex.Error{}) == :db_error
    end

    test "an unrecognised reason is :error, never the reason itself" do
      assert Health.label({:some, "new", :shape}) == :error
      assert Health.label("s3://bucket/secret") == :error
    end
  end

  defp start_monitor,
    do: start_supervised!({Health, enabled: true, interval_ms: 60_000, check_timeout_ms: 2_000})

  # A bare function plug, not the `Req.Test` stub the rest of the suite uses: the
  # checks run in tasks under the monitor, which is not in the test process's
  # ownership chain.
  defp put_signer(plug) do
    Application.put_env(:sovra, :signer,
      url: "http://signer.test",
      token: "signer-test-token",
      req_options: [plug: plug]
    )
  end

  # A router with no /ready: `:authenticate` runs before `:dispatch`, so every
  # path is 401 without a token and unknown paths are 404 with one.
  defp legacy_signer_plug(%{request_path: "/ready"} = conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [] -> conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{error: "unauthorized"})
      _ -> conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{error: "not_found"})
    end
  end

  defp legacy_signer_plug(conn), do: signer_plug(conn, kms: "ok")

  # A signer that answers both routes the health cycle uses (/ready and the
  # authenticated relayer-address call).
  defp signer_plug(%{request_path: "/ready"} = conn, kms: kms) do
    status = if kms == "ok", do: 200, else: 503

    conn
    |> Plug.Conn.put_status(status)
    |> Req.Test.json(%{status: kms, checks: %{kms: %{status: kms}}})
  end

  defp signer_plug(%{request_path: "/v1/relayer/address"} = conn, _opts),
    do: Req.Test.json(conn, %{address: "0x" <> String.duplicate("11", 20)})

  defp put_chain(chain_id, rpc_url),
    do: Application.put_env(:sovra, :ethereum, chain_id: chain_id, rpc_url: rpc_url)

  defp stub_chain_ids(map), do: Application.put_env(:sovra, :stub_chain_ids, map)

  defp restore(key, nil), do: Application.delete_env(:sovra, key)
  defp restore(key, value), do: Application.put_env(:sovra, key, value)
end
