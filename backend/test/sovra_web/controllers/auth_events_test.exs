defmodule SovraWeb.AuthEventsTest do
  @moduledoc """
  The authentication lifecycle. The two events that existed before were
  `[Auth] login ok` / `[Auth] login failed` free-text lines; the rest of the
  flow — registration, logout, refresh, password reset — was unrecorded.

  Addresses never appear: these logs leave the host for New Relic, so the keyed
  fingerprint stands in. Several tests assert that explicitly.
  """

  use SovraWeb.ConnCase, async: false

  import Sovra.LogHelpers

  alias Sovra.Log

  @password "a-very-strong-password-123"

  setup %{conn: conn} do
    Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
    on_exit(fn -> Application.delete_env(:sovra, :log_fingerprint_key) end)

    # Hammer's buckets are global and keyed on path + IP, so a file that posts
    # several times from 127.0.0.1 exhausts the 5/minute auth limit — for its
    # own later tests AND for any file that runs after it. Give every test its
    # own source address instead of resetting a shared bucket: nothing here can
    # then interfere with auth_controller_test.exs, or vice versa.
    {:ok, conn: %{conn | remote_ip: unique_ip()}}
  end

  defp unique_ip do
    n = System.unique_integer([:positive])
    {10, rem(div(n, 65_536), 256), rem(div(n, 256), 256), rem(n, 256)}
  end

  defp unique_email, do: "auth-#{System.unique_integer([:positive])}@example.gov"

  describe "registration" do
    test "auth.registered carries the user, workspace and a fingerprint", %{conn: conn} do
      email = unique_email()

      {conn, events} =
        capture_events(fn ->
          post(conn, ~p"/dashboard/auth/register", %{
            email: email,
            password: @password,
            full_name: "Ada Lovelace",
            workspace_name: "Registry"
          })
        end)

      assert conn.status == 201

      event = assert_event(events, "auth.registered", email_domain: "example.gov")
      assert event.metadata[:email_fp] == Log.fingerprint(email)
      assert event.metadata[:user_id]
      assert event.metadata[:workspace_id]
      refute inspect(event.metadata) =~ "auth-"
    end

    test "a duplicate address is rejected with its own reason", %{conn: conn} do
      email = unique_email()

      params = %{
        email: email,
        password: @password,
        full_name: "Ada Lovelace",
        workspace_name: "Registry"
      }

      assert post(conn, ~p"/dashboard/auth/register", params).status == 201

      {conn, events} =
        capture_events(fn -> post(conn, ~p"/dashboard/auth/register", params) end)

      # The response deliberately does not disclose that the address is taken;
      # the log may, because it never leaves for the client.
      assert conn.status == 422
      assert Jason.decode!(conn.resp_body)["error"] == "registration_failed"

      event = assert_event(events, "auth.registration.rejected", reason: :email_taken)
      assert event.metadata[:email_fp] == Log.fingerprint(email)
    end

    test "validation failures log field names, never the submitted values", %{conn: conn} do
      {conn, events} =
        capture_events(fn ->
          post(conn, ~p"/dashboard/auth/register", %{
            email: unique_email(),
            password: "short",
            full_name: "Ada Lovelace",
            workspace_name: "Registry"
          })
        end)

      assert conn.status == 422

      event = assert_event(events, "auth.registration.rejected", reason: :validation_error)
      assert event.metadata[:invalid_fields] =~ "password"
      refute inspect(event.metadata) =~ "short"
      refute inspect(event.metadata) =~ "Ada Lovelace"
    end
  end

  describe "login" do
    setup %{conn: conn} do
      email = unique_email()

      post(conn, ~p"/dashboard/auth/register", %{
        email: email,
        password: @password,
        full_name: "Ada Lovelace",
        workspace_name: "Registry"
      })

      %{email: email}
    end

    test "success records the user and the workspace it landed on", %{
      conn: conn,
      email: email
    } do
      {conn, events} =
        capture_events(fn ->
          post(conn, ~p"/dashboard/auth/login", %{email: email, password: @password})
        end)

      assert conn.status == 200

      event = assert_event(events, "auth.login.succeeded")
      assert event.metadata[:email_fp] == Log.fingerprint(email)
      assert event.metadata[:user_id]
    end

    test "failure is a warning with a fingerprint, so attempts are countable", %{
      conn: conn,
      email: email
    } do
      {conn, events} =
        capture_events(fn ->
          post(conn, ~p"/dashboard/auth/login", %{email: email, password: "wrong-password"})
        end)

      assert conn.status == 401

      event =
        assert_event(events, "auth.login.failed",
          reason: :invalid_credentials,
          email_domain: "example.gov"
        )

      assert event.level == :warning
      assert event.metadata[:email_fp] == Log.fingerprint(email)
      refute inspect(event.metadata) =~ "auth-"
      refute inspect(event.metadata) =~ "wrong-password"
    end

    test "an unknown address is still fingerprinted, so sweeps are visible", %{conn: conn} do
      stranger = unique_email()

      {_conn, events} =
        capture_events(fn ->
          post(conn, ~p"/dashboard/auth/login", %{email: stranger, password: @password})
        end)

      event = assert_event(events, "auth.login.failed")
      assert event.metadata[:email_fp] == Log.fingerprint(stranger)
    end
  end

  describe "session lifecycle" do
    setup %{conn: conn} do
      email = unique_email()

      conn =
        post(conn, ~p"/dashboard/auth/register", %{
          email: email,
          password: @password,
          full_name: "Ada Lovelace",
          workspace_name: "Registry"
        })

      %{conn: conn, email: email}
    end

    test "logout is recorded", %{conn: conn} do
      {conn, events} = capture_events(fn -> post(conn, ~p"/dashboard/auth/logout") end)

      assert conn.status == 200
      assert_event(events, "auth.logged_out")
    end

    test "a refresh with no cookie is rejected with its own reason", %{conn: _conn} do
      # A fresh conn, so no refresh cookie is presented at all.
      {conn, events} =
        capture_events(fn ->
          Phoenix.ConnTest.build_conn() |> post(~p"/dashboard/auth/refresh")
        end)

      assert conn.status == 401
      assert_event(events, "auth.session.refresh_rejected", reason: :no_refresh_cookie)
    end

    test "a successful refresh is recorded", %{conn: conn} do
      {conn, events} = capture_events(fn -> post(conn, ~p"/dashboard/auth/refresh") end)

      assert conn.status == 200
      assert_event(events, "auth.session.refreshed")
    end
  end

  describe "password reset" do
    test "a request is logged whether or not the address exists", %{conn: conn} do
      stranger = unique_email()

      {conn, events} =
        capture_events(fn ->
          post(conn, ~p"/dashboard/auth/password/reset-request", %{email: stranger})
        end)

      # The endpoint always answers ok to prevent enumeration, and the log
      # mirrors that: inferring existence from our own logs would reintroduce
      # exactly what the response hides.
      assert conn.status == 200

      event = assert_event(events, "auth.password_reset.requested")
      assert event.metadata[:email_fp] == Log.fingerprint(stranger)
    end

    test "a bad token is rejected with a reason", %{conn: conn} do
      {conn, events} =
        capture_events(fn ->
          post(conn, ~p"/dashboard/auth/password/reset", %{
            token: "not-a-real-token",
            password: @password
          })
        end)

      assert conn.status == 422
      assert_event(events, "auth.password_reset.rejected")
    end
  end
end
