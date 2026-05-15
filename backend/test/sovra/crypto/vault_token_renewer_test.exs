defmodule Sovra.Crypto.VaultTokenRenewerTest do
  # Not async: VaultTokenRenewer is named globally and Req.Test runs in
  # shared mode so the GenServer (a separate pid) can find the stub
  # registered by the test.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Sovra.Crypto.VaultTokenRenewer

  setup do
    Req.Test.set_req_test_to_shared(self())
    :ok
  end

  # Some tests assert on :info-level logs; the test config sets the global
  # Logger level to :warning, which would drop the messages before
  # capture_log sees them (see ExUnit.CaptureLog docs). This setup
  # temporarily lowers the level for those tests.
  defp lower_log_level_to_info(_context) do
    previous = Logger.level()
    Logger.configure(level: :info)
    on_exit(fn -> Logger.configure(level: previous) end)
    :ok
  end

  describe "init/1" do
    test "performs a renewal immediately at boot so every restart extends the token" do
      test_pid = self()

      Req.Test.stub(:sovra_vault, fn conn ->
        send(
          test_pid,
          {:vault_request, conn.method, conn.request_path,
           Plug.Conn.get_req_header(conn, "x-vault-token")}
        )

        Req.Test.json(conn, renew_response_body())
      end)

      start_supervised!(VaultTokenRenewer)

      # The renewer must POST renew-self with the x-vault-token header
      # carrying the configured token. test.exs sets token: "test-token".
      assert_receive {:vault_request, "POST", "/v1/auth/token/renew-self", ["test-token"]}, 500
    end

    @tag :info_logs
    test "logs the configured interval in hours" do
      Req.Test.stub(:sovra_vault, fn conn -> Req.Test.json(conn, %{}) end)

      log =
        capture_log(fn ->
          start_supervised!(VaultTokenRenewer)
          Process.sleep(50)
        end)

      assert log =~ "VaultTokenRenewer started, renewing every"
      assert log =~ "hours"
      refute log =~ "minutes"
    end
  end

  describe "handle_info(:renew, _)" do
    @tag :info_logs
    test "logs success at :info with policies and ttl extracted from the response" do
      Req.Test.stub(:sovra_vault, fn conn ->
        Req.Test.json(conn, renew_response_body())
      end)

      log =
        capture_log(fn ->
          start_supervised!(VaultTokenRenewer)
          Process.sleep(100)
        end)

      assert log =~ "Vault token renewed"
      # Pulled from the response body so a mis-policied token is visible.
      assert log =~ ~s(policies=["default", "sovra-transit"])
      assert log =~ "ttl=345600s"
    end

    @tag :info_logs
    test "success log omits the metadata suffix gracefully when the response is empty" do
      Req.Test.stub(:sovra_vault, fn conn -> Req.Test.json(conn, %{}) end)

      log =
        capture_log(fn ->
          start_supervised!(VaultTokenRenewer)
          Process.sleep(100)
        end)

      # No "(policies=…, ttl=…)" suffix when the body has no `auth`.
      assert log =~ "Vault token renewed\n"
      refute log =~ "policies="
      refute log =~ "ttl="
    end

    test "logs first failure at :error and retries at retry_interval" do
      test_pid = self()

      Req.Test.stub(:sovra_vault, fn conn ->
        send(test_pid, :vault_request)
        Plug.Conn.send_resp(conn, 503, "boom")
      end)

      log =
        capture_log(fn ->
          start_supervised!(VaultTokenRenewer)

          # Boot renewal + first retry (retry_interval = 50 ms in test config).
          assert_receive :vault_request, 500
          assert_receive :vault_request, 500
        end)

      assert log =~ "[error]"
      assert log =~ "Vault token renewal failed (consecutive=1)"
    end

    test "subsequent failures log at :warning, not :error" do
      Req.Test.stub(:sovra_vault, fn conn ->
        Plug.Conn.send_resp(conn, 503, "boom")
      end)

      log =
        capture_log(fn ->
          start_supervised!(VaultTokenRenewer)
          # Long enough for boot + 2 retries (50 ms each).
          Process.sleep(300)
        end)

      # Exactly one :error line (the first failure of the streak).
      error_lines =
        log
        |> String.split("\n", trim: true)
        |> Enum.filter(&(&1 =~ "[error]" and &1 =~ "Vault token renewal failed"))

      assert length(error_lines) == 1

      warning_lines =
        log
        |> String.split("\n", trim: true)
        |> Enum.filter(&(&1 =~ "[warning]" and &1 =~ "Vault token renewal failed"))

      assert length(warning_lines) >= 1
    end

    @tag :info_logs
    test "recovery after failure resets the streak and logs the recovery" do
      test_pid = self()
      counter = :counters.new(1, [])

      Req.Test.stub(:sovra_vault, fn conn ->
        :counters.add(counter, 1, 1)
        n = :counters.get(counter, 1)
        send(test_pid, {:vault_request, n})

        if n == 1 do
          Plug.Conn.send_resp(conn, 503, "boom")
        else
          Req.Test.json(conn, %{})
        end
      end)

      log =
        capture_log(fn ->
          start_supervised!(VaultTokenRenewer)
          assert_receive {:vault_request, 1}, 500
          assert_receive {:vault_request, 2}, 500
          # Settle the recovery log line.
          Process.sleep(50)
        end)

      assert log =~ "Vault token renewed (recovered after 1 failure(s))"
      assert :sys.get_state(VaultTokenRenewer).consecutive_failures == 0
    end

    test "transport-level errors flow through the normal failure path" do
      # Distinct from the rescue test below: this exercises the
      # `{:error, reason}` branch of Req.post — what Req returns for
      # connection refusals, DNS failures, TLS errors, etc.
      Req.Test.stub(:sovra_vault, fn conn ->
        Req.Test.transport_error(conn, :econnrefused)
      end)

      log =
        capture_log(fn ->
          {:ok, pid} = start_supervised(VaultTokenRenewer)
          Process.sleep(150)
          assert Process.alive?(pid)
        end)

      assert log =~ "Vault token renewal failed"
      assert log =~ "vault_renew_error"
      assert log =~ "econnrefused"
    end

    test "an exception raised inside the Req call is captured, not propagated to the supervisor" do
      # Simulate a transport-level failure that Req surfaces as a raised
      # exception rather than {:error, _}. If unhandled, this would crash
      # the GenServer; init/1 immediately re-sends :renew on restart, so an
      # unhandled raise would crash-loop until the supervisor's max_restarts
      # trips and takes down Sovra.Supervisor.
      Req.Test.stub(:sovra_vault, fn _conn ->
        raise "transport boom"
      end)

      log =
        capture_log(fn ->
          {:ok, pid} = start_supervised(VaultTokenRenewer)
          # Boot renewal + a couple of retries.
          Process.sleep(200)
          # The GenServer must still be alive — the rescue clause turned the
          # raise into {:error, _} which the normal failure path handles.
          assert Process.alive?(pid)
        end)

      assert log =~ "Vault token renewal failed"
      assert log =~ "vault_renew_exception"
    end

    test "after max_consecutive_failures, switches from fast retry to bounded degraded cadence" do
      # Test config: retry_interval=50ms, degraded_interval=300ms,
      # max_consecutive_failures=3, interval=5_000ms.
      test_pid = self()

      Req.Test.stub(:sovra_vault, fn conn ->
        send(test_pid, :vault_request)
        Plug.Conn.send_resp(conn, 503, "boom")
      end)

      start_supervised!(VaultTokenRenewer)

      # Boot renewal + 2 retries — these are the failures that drive the counter
      # to max_consecutive_failures (3).
      assert_receive :vault_request, 500
      assert_receive :vault_request, 500
      assert_receive :vault_request, 500

      assert :sys.get_state(VaultTokenRenewer).consecutive_failures == 3

      # The next attempt is no longer at retry_interval (50 ms) — confirm
      # nothing arrives in a window well past 50 ms but well below 300 ms.
      refute_receive :vault_request, 100

      # But the renewer must NOT have gone silent until the next 5_000 ms tick;
      # it should keep trying at degraded_interval. Verify the next attempt
      # lands within a window comfortably past degraded_interval.
      assert_receive :vault_request, 500
    end
  end

  setup context do
    if context[:info_logs], do: lower_log_level_to_info(context), else: :ok
  end

  # Approximates Vault's `POST /v1/auth/token/renew-self` 200 response.
  # Only the fields the renewer reads are populated; the renewer must not
  # rely on anything else.
  defp renew_response_body do
    %{
      "auth" => %{
        "client_token" => "test-token",
        "policies" => ["default", "sovra-transit"],
        "token_policies" => ["default", "sovra-transit"],
        "lease_duration" => 345_600,
        "renewable" => true
      }
    }
  end
end
