defmodule SovraWeb.HealthControllerTest do
  # async: false — the readiness monitor is a named singleton and the checks read
  # global config. Shared-mode sandbox lets the monitor reach the same connection.
  use SovraWeb.ConnCase, async: false

  alias Sovra.BuildInfo
  alias Sovra.Health

  setup do
    prev = %{
      ethereum: Application.get_env(:sovra, :ethereum),
      signer: Application.get_env(:sovra, :signer),
      stub_chain_ids: Application.get_env(:sovra, :stub_chain_ids)
    }

    Application.put_env(:sovra, :ethereum, [])
    Application.put_env(:sovra, :signer, [])

    on_exit(fn -> Enum.each(prev, fn {key, value} -> restore(key, value) end) end)

    :ok
  end

  describe "GET /health" do
    # Liveness only, and it must stay that way: the Cloudflare tunnel and the
    # deploy gate point at it, so a dependency must never be able to fail it.
    test "is 200 regardless of dependency state", %{conn: conn} do
      put_chain(31_337, "http://down.test")
      stub_chain_ids(%{"http://down.test" => {:error, :chain_id_unreachable}})

      start_monitor()
      assert %{status: :error} = Health.check_now()

      assert %{"status" => "ok"} = conn |> get(~p"/health") |> json_response(200)
    end

    # The deploy asserts on this per node, so the values matter, not just the keys.
    test "carries the build identity, and stays free of I/O", %{conn: conn} do
      body = conn |> get(~p"/health") |> json_response(200)

      assert body == %{
               "status" => "ok",
               "revision" => BuildInfo.revision(),
               "ref" => BuildInfo.ref(),
               "version" => BuildInfo.version(),
               "built_at" => BuildInfo.built_at()
             }

      # No monitor started: a dependency read would surface here.
      refute Process.whereis(Health)
    end
  end

  describe "GET /ready" do
    test "503 unavailable when the monitor is not running", %{conn: conn} do
      body = conn |> get(~p"/ready") |> json_response(503)

      assert body == %{"status" => "unavailable", "checked_at" => nil, "checks" => %{}}
    end

    test "200 with a per-dependency breakdown when everything is up", %{conn: conn} do
      start_monitor()
      assert %{status: :ok} = Health.check_now()

      body = conn |> get(~p"/ready") |> json_response(200)

      assert body["status"] == "ok"
      assert {:ok, _, _} = DateTime.from_iso8601(body["checked_at"])
      assert body["checks"]["database"]["status"] == "ok"
      assert body["checks"]["signer"]["status"] == "skipped"
      assert body["checks"]["signer_kms"]["status"] == "skipped"
      assert is_integer(body["checks"]["database"]["took_ms"])
    end

    test "chains are keyed by chain id and carry their name", %{conn: conn} do
      Application.put_env(:sovra, :ethereum,
        chain_id: 31_337,
        chain_name: "anvil",
        rpc_url: "http://rpc.test"
      )

      stub_chain_ids(%{"http://rpc.test" => {:ok, 31_337}})

      start_monitor()
      assert %{status: :ok} = Health.check_now()

      body = conn |> get(~p"/ready") |> json_response(200)

      assert %{"31337" => %{"status" => "ok", "chain_name" => "anvil", "took_ms" => took_ms}} =
               body["checks"]["rpc"]

      assert is_integer(took_ms)
    end

    test "503 when a single dependency is down", %{conn: conn} do
      put_chain(31_337, "http://down.test")
      stub_chain_ids(%{"http://down.test" => {:error, :chain_id_unreachable}})

      start_monitor()
      assert %{status: :error} = Health.check_now()

      body = conn |> get(~p"/ready") |> json_response(503)

      assert body["status"] == "error"
      # The rest of the report still comes back — an operator needs to see which
      # dependency failed, not just that one did.
      assert body["checks"]["database"]["status"] == "ok"
      assert body["checks"]["rpc"]["31337"]["error"] == "unreachable"
    end

    test "503 starting while the first cycle is still running", %{conn: conn} do
      put_chain(31_337, "http://slow.test")
      stub_chain_ids(%{"http://slow.test" => fn -> Process.sleep(500) && {:ok, 31_337} end})

      start_monitor()

      body = conn |> get(~p"/ready") |> json_response(503)

      assert body["status"] == "starting"
    end

    # No build identity here: that is /health's job, and this body is what a
    # dependency poll parses.
    test "carries no build identity", %{conn: conn} do
      start_monitor()

      body = conn |> get(~p"/ready") |> json_response(503)

      refute Map.has_key?(body, "revision")
      refute Map.has_key?(body, "version")
    end

    # The route is unauthenticated and reachable from the public edge, so the
    # body must never carry a reason term, a URL, or anything else internal.
    test "the body carries closed-set labels, never a raw reason", %{conn: conn} do
      Application.put_env(:sovra, :signer,
        url: "http://signer.test/secret-signer-path",
        token: "super-secret-token",
        req_options: [plug: fn c -> Req.Test.transport_error(c, :econnrefused) end]
      )

      start_monitor()
      assert %{status: :error} = Health.check_now()

      raw = conn |> get(~p"/ready") |> response(503)

      assert Jason.decode!(raw)["checks"]["signer"]["error"] == "unreachable"
      refute raw =~ "super-secret-token"
      refute raw =~ "secret-signer-path"
      refute raw =~ "econnrefused"
      refute raw =~ "TransportError"
    end
  end

  defp start_monitor,
    do: start_supervised!({Health, enabled: true, interval_ms: 60_000, check_timeout_ms: 2_000})

  defp put_chain(chain_id, rpc_url),
    do: Application.put_env(:sovra, :ethereum, chain_id: chain_id, rpc_url: rpc_url)

  defp stub_chain_ids(map), do: Application.put_env(:sovra, :stub_chain_ids, map)

  defp restore(key, nil), do: Application.delete_env(:sovra, key)
  defp restore(key, value), do: Application.put_env(:sovra, key, value)
end
