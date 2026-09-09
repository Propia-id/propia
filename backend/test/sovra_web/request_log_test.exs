defmodule SovraWeb.RequestLogTest do
  # async: false — asserting on :info means moving the global Logger level.
  use SovraWeb.ConnCase, async: false

  import ExUnit.CaptureLog

  alias SovraWeb.RequestLog

  @fields [:event, :route, :status, :duration_ms, :user_id, :workspace_id]

  setup %{conn: conn} do
    original = Logger.level()
    Logger.configure(level: :info)
    on_exit(fn -> Logger.configure(level: original) end)

    # Hammer's auth buckets are global and keyed on path + IP. Same workaround
    # as auth_events_test.exs: a source address per test.
    n = System.unique_integer([:positive])
    ip = {10, rem(div(n, 65_536), 256), rem(div(n, 256), 256), rem(n, 256)}

    {:ok, conn: %{conn | remote_ip: ip}}
  end

  defp capture(fun) do
    capture_log([format: "$metadata[$level]|$message\n", metadata: @fields], fun)
  end

  defp lines(log), do: String.split(log, "\n", trim: true)

  # For what a request cannot produce on demand: a probe that fails.
  defp emit(conn_fields) do
    conn = Map.merge(%{method: "GET", request_path: "/", status: 200}, conn_fields)

    capture(fn ->
      RequestLog.handle_event(
        [:phoenix, :endpoint, :stop],
        %{duration: System.convert_time_unit(3, :millisecond, :native)},
        %{conn: conn},
        nil
      )
    end)
  end

  defp bad_login(conn) do
    post(conn, "/dashboard/auth/login", %{"email" => "nobody@example.test", "password" => "no"})
  end

  describe "http.request" do
    test "is one line per request, carrying the route and the outcome", %{conn: conn} do
      log = capture(fn -> bad_login(conn) end)

      assert [line] = Enum.filter(lines(log), &(&1 =~ "event=http.request"))
      assert line =~ "route=/dashboard/auth/login"
      assert line =~ "status=401"
      assert line =~ ~r/duration_ms=\d+\.\d+/
      assert line =~ "POST /dashboard/auth/login"
      assert line =~ "[warning]"
    end

    test "records the route pattern, not the ids in the path", %{conn: conn} do
      log =
        capture(fn -> post(conn, "/dashboard/workspaces/#{Ecto.UUID.generate()}/switch", %{}) end)

      assert [line] = Enum.filter(lines(log), &(&1 =~ "event=http.request"))
      assert line =~ "route=/dashboard/workspaces/:workspace_id/switch"
      assert line =~ "POST /dashboard/workspaces/"
    end

    test "an unmatched path contributes one value, not one per probe", %{conn: conn} do
      log = capture(fn -> get(conn, "/nope-#{System.unique_integer([:positive])}") end)

      assert [line] = Enum.filter(lines(log), &(&1 =~ "event=http.request"))
      assert line =~ "route=unmatched"
    end

    test "replaces Phoenix's own prose lines", %{conn: conn} do
      log = capture(fn -> bad_login(conn) end)

      refute log =~ "Sent 401 in"

      assert Enum.all?(
               lines(log),
               &(&1 =~ "event=auth.login.failed" or &1 =~ "event=http.request")
             )
    end
  end

  describe "levels" do
    test "5xx is an error", do: assert(emit(%{status: 503}) =~ "[error]")
    test "4xx is a warning", do: assert(emit(%{status: 422}) =~ "[warning]")
    test "anything else is info", do: assert(emit(%{status: 302}) =~ "[info]")
  end

  describe "probes" do
    test "a healthy probe is not logged", %{conn: conn} do
      assert capture(fn -> get(conn, "/health") end) == ""
    end

    test "a failing one is" do
      assert emit(%{request_path: "/health", status: 503}) =~ "status=503"
    end

    test "so is one that never got a status" do
      assert emit(%{request_path: "/health", status: nil}) =~ "event=http.request"
    end
  end

  test "a handler that raises does not take the request with it" do
    log =
      capture_log(fn -> RequestLog.handle_event([:phoenix, :endpoint, :stop], %{}, %{}, nil) end)

    assert log =~ "Request log handler failed"
  end
end
