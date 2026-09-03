defmodule Sovra.Verification.RequestEventsTest do
  @moduledoc """
  The verification funnel before a holder submits anything: a session is
  created, the wallet fetches the signed request behind the QR, and abandoned
  sessions are swept.

  Together with `presentation.received`, these three make the drop-off legible
  — a QR that is shown but never scanned looks identical to a broken wallet
  until `presentation.request.fetched` separates them.
  """

  use SovraWeb.ConnCase, async: false

  import Sovra.LogHelpers

  alias Sovra.Verification
  alias Sovra.Verification.ExpiredSessionsSweeper

  defp dcql_query do
    %{
      "credentials" => [
        %{
          "id" => "diploma",
          "format" => "vc+sd-jwt",
          "claims" => [%{"path" => ["studentName"]}]
        }
      ]
    }
  end

  defp verifier_workspace, do: provision_workspace(fixture_workspace().workspace)

  # :utc_datetime rejects microseconds.
  defp expire!(session) do
    past = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second)

    session
    |> Ecto.Changeset.change(expires_at: past)
    |> Sovra.Repo.update!()
  end

  describe "presentation.request.created" do
    test "records the verification id and how many credentials were asked for" do
      ws = verifier_workspace()

      {{:ok, %{session: session}}, events} =
        capture_events(fn -> Verification.create_session(ws.id, dcql_query()) end)

      assert_event(events, "presentation.request.created",
        verification_id: session.id,
        workspace_id: ws.id,
        dcql_credential_count: 1
      )
    end

    test "a malformed DCQL query is rejected with a reason" do
      ws = verifier_workspace()

      {{:error, :invalid_dcql_query}, events} =
        capture_events(fn -> Verification.create_session(ws.id, %{"credentials" => []}) end)

      assert_event(events, "presentation.request.rejected",
        workspace_id: ws.id,
        reason: :invalid_dcql_query
      )
    end
  end

  describe "presentation.request.fetched" do
    test "fires when the wallet pulls the signed request behind the QR", %{conn: conn} do
      ws = verifier_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      {conn, events} =
        capture_events(fn -> get(conn, ~p"/wallet/verifier/request/#{session.id}") end)

      assert conn.status == 200

      assert_event(events, "presentation.request.fetched",
        verification_id: session.id,
        workspace_id: ws.id
      )
    end

    test "a stale QR is distinguishable from a session that never existed", %{conn: conn} do
      ws = verifier_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      # Age the session past its expiry: the endpoint 404s either way, so the
      # reason is the only thing that separates the two causes.
      expire!(session)

      {conn, events} =
        capture_events(fn -> get(conn, ~p"/wallet/verifier/request/#{session.id}") end)

      assert conn.status == 404
      assert_event(events, "presentation.request.rejected", reason: :session_expired)

      unknown = Ecto.UUID.generate()

      {conn, events} =
        capture_events(fn -> get(conn, ~p"/wallet/verifier/request/#{unknown}") end)

      assert conn.status == 404

      assert_event(events, "presentation.request.rejected",
        verification_id: unknown,
        reason: :session_not_found
      )
    end
  end

  describe "presentation.request.expired" do
    test "the sweeper reports how many sessions it abandoned" do
      ws = verifier_workspace()
      {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

      expire!(session)

      {:ok, events} =
        capture_events(fn ->
          ExpiredSessionsSweeper.perform(%Oban.Job{id: 1, attempt: 1, args: %{}})
        end)

      event = assert_event(events, "presentation.request.expired")
      assert event.metadata[:count] >= 1
    end

    test "a quiet sweep says nothing" do
      {:ok, events} =
        capture_events(fn ->
          ExpiredSessionsSweeper.perform(%Oban.Job{id: 1, attempt: 1, args: %{}})
        end)

      refute_event(events, "presentation.request.expired")
    end
  end
end
