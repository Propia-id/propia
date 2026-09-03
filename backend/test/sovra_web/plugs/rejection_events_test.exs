defmodule SovraWeb.Plugs.RejectionEventsTest do
  @moduledoc """
  The plugs' 4xx rejections used to be entirely silent, which left no way to
  detect abuse or to answer "our API key stopped working". These assert on the
  *metadata*, not the message, because that is what the New Relic conditions
  read.
  """

  use SovraWeb.ConnCase, async: false

  import Sovra.LogHelpers

  alias Sovra.Workspaces.ApiKeys
  alias SovraWeb.Plugs.ApiKeyPlug
  alias SovraWeb.Plugs.OriginCheckPlug
  alias SovraWeb.Plugs.RateLimitPlug
  alias SovraWeb.Plugs.RequireAdminPlug
  alias SovraWeb.Plugs.RequireOrgAdminPlug
  alias SovraWeb.Plugs.RequireWorkspaceAdminPlug

  describe "auth.api_key.rejected" do
    test "distinguishes a missing credential from a refused one", %{conn: conn} do
      {_, events} = capture_events(fn -> ApiKeyPlug.call(conn, []) end)

      event = assert_event(events, "auth.api_key.rejected", reason: :missing)
      assert event.level == :warning
    end

    test "tags a malformed authorization header", %{conn: conn} do
      {_, events} =
        capture_events(fn ->
          conn |> put_req_header("authorization", "Basic abc") |> ApiKeyPlug.call([])
        end)

      assert_event(events, "auth.api_key.rejected", reason: :malformed_header)
    end

    test "tags an unknown key as invalid and never logs the key itself", %{conn: conn} do
      {_, events} =
        capture_events(fn ->
          conn
          |> put_req_header("authorization", "Bearer sovra_sk_deadbeefdeadbeef")
          |> ApiKeyPlug.call([])
        end)

      event = assert_event(events, "auth.api_key.rejected", reason: :invalid)
      refute inspect(event.metadata) =~ "deadbeef"
      refute event.message =~ "deadbeef"
    end

    test "a revoked key is refused and logged", %{conn: conn} do
      %{workspace: ws} = fixture_workspace()
      {:ok, %{api_key: plaintext, record: record}} = ApiKeys.create_api_key(ws.id, "Prod")
      {:ok, _} = ApiKeys.revoke_api_key(record)

      {_, events} =
        capture_events(fn ->
          conn
          |> put_req_header("authorization", "Bearer #{plaintext}")
          |> ApiKeyPlug.call([])
        end)

      assert_event(events, "auth.api_key.rejected", reason: :invalid)
    end

    test "a valid key logs nothing", %{conn: conn} do
      %{workspace: ws} = fixture_workspace()
      {:ok, %{api_key: plaintext}} = ApiKeys.create_api_key(ws.id, "Prod")

      {result, events} =
        capture_events(fn ->
          conn
          |> put_req_header("authorization", "Bearer #{plaintext}")
          |> ApiKeyPlug.call([])
        end)

      refute result.halted
      refute_event(events, "auth.api_key.rejected")
    end
  end

  describe "auth.rate_limit.denied" do
    test "fires once the bucket is exhausted, fingerprinting the caller", %{conn: conn} do
      Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
      on_exit(fn -> Application.delete_env(:sovra, :log_fingerprint_key) end)

      {denied, events} = exhaust(conn)

      assert denied.status == 429
      event = assert_event(events, "auth.rate_limit.denied")
      assert event.metadata[:max_requests] == 1
      # 127.0.0.1 is the test conn's remote_ip. With a key configured only the
      # fingerprint ships, under a name that says so.
      assert event.metadata[:ip_fp] == Sovra.Log.fingerprint("127.0.0.1")
      refute Map.has_key?(event.metadata, :ip)
      refute inspect(event.metadata) =~ "127.0.0.1"
    end

    test "falls back to the raw address when no key is configured", %{conn: conn} do
      Application.delete_env(:sovra, :log_fingerprint_key)

      {_denied, events} = exhaust(conn)

      # The attribute NAME is what changes, so a query never mixes digests and
      # raw values under a key claiming to hold digests — and
      # `metadata.ip IS NOT NULL` detects a node running without a key.
      event = assert_event(events, "auth.rate_limit.denied", ip: "127.0.0.1")
      refute Map.has_key?(event.metadata, :ip_fp)
    end

    defp exhaust(conn) do
      opts = RateLimitPlug.init(max_requests: 1, window_ms: 60_000)
      path = "/dashboard/auth/login-#{System.unique_integer([:positive])}"
      conn = %{conn | request_path: path}

      _allowed = RateLimitPlug.call(conn, opts)
      capture_events(fn -> RateLimitPlug.call(conn, opts) end)
    end
  end

  describe "auth.origin.rejected" do
    test "records the offending origin, which is usually a stale config", %{conn: conn} do
      {rejected, events} =
        capture_events(fn ->
          %{conn | method: "POST"}
          |> put_req_header("origin", "https://evil.example.com")
          |> OriginCheckPlug.call([])
        end)

      assert rejected.status == 403

      assert_event(events, "auth.origin.rejected",
        reason: :not_allowed,
        origin: "https://evil.example.com"
      )
    end

    test "a safe method is never checked or logged", %{conn: conn} do
      {_, events} =
        capture_events(fn ->
          conn
          |> put_req_header("origin", "https://evil.example.com")
          |> OriginCheckPlug.call([])
        end)

      refute_event(events, "auth.origin.rejected")
    end
  end

  describe "authz.denied" do
    test "separates no-session from insufficient-role on a workspace", %{conn: conn} do
      %{workspace: ws, owner: owner} = fixture_workspace()

      {_, events} =
        capture_events(fn -> RequireWorkspaceAdminPlug.call(conn, []) end)

      assert_event(events, "authz.denied",
        reason: :no_session,
        required_role: "workspace_admin"
      )

      # A real session, but the workspace cannot be resolved from the request.
      # fetch_query_params/1 because resolve_workspace_id/1 falls through to
      # conn.params, which raises while unfetched — real requests always have
      # them, having passed Plug.Parsers in the endpoint.
      {_, events} =
        capture_events(fn ->
          conn
          |> fetch_query_params()
          |> assign(:current_user, %{user_id: owner.id, workspace_id: nil, is_admin: false})
          |> RequireWorkspaceAdminPlug.call([])
        end)

      assert_event(events, "authz.denied", reason: :no_workspace_id)

      # A member of the workspace, but not an admin.
      %{owner: outsider} = fixture_workspace()
      {:ok, _} = Sovra.Workspaces.add_member(ws.id, outsider.id, "member")

      {_, events} =
        capture_events(fn ->
          conn
          |> assign(:current_user, %{user_id: outsider.id, workspace_id: ws.id, is_admin: false})
          |> Map.put(:path_params, %{"workspace_id" => ws.id})
          |> RequireWorkspaceAdminPlug.call([])
        end)

      assert_event(events, "authz.denied",
        reason: :insufficient_role,
        actual_role: "member"
      )
    end

    test "a non-member of an org gets 404 and a tagged event", %{conn: conn} do
      %{org: org} = fixture_workspace()
      outsider = fixture_user()

      {denied, events} =
        capture_events(fn ->
          conn
          |> assign(:current_user, %{user_id: outsider.id, workspace_id: nil, is_admin: false})
          |> Map.put(:path_params, %{"org_id" => org.id})
          |> RequireOrgAdminPlug.call([])
        end)

      # 404 rather than 403: an org's existence is not disclosed to non-members.
      assert denied.status == 404
      assert_event(events, "authz.denied", reason: :not_a_member, org_id: org.id)
    end

    test "the platform admin gate tags which of the two failures it was", %{conn: conn} do
      {_, events} = capture_events(fn -> RequireAdminPlug.call(conn, []) end)
      assert_event(events, "authz.denied", reason: :no_session, required_role: "platform_admin")

      {_, events} =
        capture_events(fn ->
          conn
          |> assign(:current_user, %{user_id: "u", workspace_id: nil, is_admin: false})
          |> RequireAdminPlug.call([])
        end)

      assert_event(events, "authz.denied", reason: :insufficient_role)
    end

    test "a malformed id param is a 403, not a 500", %{conn: conn} do
      # `?workspace_id[]=1` arrives as a list: non-nil and non-binary, so the
      # `with` guard fails and the else clause sees an unmatched term. Tagging
      # the denial reasons dropped the original `_ ->` catch-all, which turned
      # every one of these into a WithClauseError — a 500 on a path that is
      # meant to answer 403.
      for {plug, param, error} <- [
            {RequireWorkspaceAdminPlug, "workspace_id", "workspace_admin_required"},
            {RequireOrgAdminPlug, "org_id", "org_admin_required"},
            {SovraWeb.Plugs.RequireOrgOwnerPlug, "org_id", "org_owner_required"}
          ] do
        conn =
          conn
          |> Map.put(:params, %{param => ["injected"]})
          |> assign(:current_user, %{
            user_id: Ecto.UUID.generate(),
            workspace_id: nil,
            is_admin: false
          })

        {denied, events} = capture_events(fn -> plug.call(conn, []) end)

        assert denied.status == 403, "#{inspect(plug)} did not answer 403"
        assert Jason.decode!(denied.resp_body) == %{"error" => error}
        assert_event(events, "authz.denied")
      end
    end

    test "an admin passes without an event", %{conn: conn} do
      {result, events} =
        capture_events(fn ->
          conn
          |> assign(:current_user, %{user_id: "u", workspace_id: nil, is_admin: true})
          |> RequireAdminPlug.call([])
        end)

      refute result.halted
      refute_event(events, "authz.denied")
    end
  end
end
