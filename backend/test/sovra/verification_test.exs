defmodule Sovra.VerificationTest do
  use Sovra.DataCase, async: false

  alias Sovra.Organizations.Organization
  alias Sovra.Verification
  alias Sovra.Workspaces.Workspace

  defp create_user, do: fixture_user()

  defp create_workspace do
    %{workspace: ws, org: org} = fixture_workspace(name: "Verifier")
    %{workspace: provision_workspace(ws), organization: org}
  end

  defp dcql_query do
    %{
      "credentials" => [
        %{
          "id" => "diploma",
          "format" => "jwt_vc_json",
          "claims" => [%{"path" => ["studentName"]}, %{"path" => ["degree"]}]
        }
      ]
    }
  end

  describe "create_session/3" do
    test "creates a pending session and returns the authorization request URI" do
      %{workspace: ws} = create_workspace()

      assert {:ok, %{session: s, authorization_request_uri: uri}} =
               Verification.create_session(ws.id, dcql_query())

      assert s.id
      assert s.status == "pending"
      assert s.workspace_id == ws.id
      assert is_binary(s.nonce)
      assert is_binary(s.state)
      assert DateTime.compare(s.expires_at, DateTime.utc_now()) == :gt
      assert String.starts_with?(uri, "openid4vp://")
      assert String.contains?(uri, "response_mode=direct_post")
      assert String.contains?(uri, URI.encode_www_form(s.state))
      assert String.contains?(uri, URI.encode_www_form(s.nonce))
    end

    test "returns :invalid_dcql_query when DCQL is empty" do
      %{workspace: ws} = create_workspace()
      assert {:error, :invalid_dcql_query} = Verification.create_session(ws.id, %{})
    end

    test "returns :invalid_dcql_query when credentials list is empty" do
      %{workspace: ws} = create_workspace()

      assert {:error, :invalid_dcql_query} =
               Verification.create_session(ws.id, %{"credentials" => []})
    end

    test "returns :workspace_not_found for unknown workspace" do
      assert {:error, :workspace_not_found} =
               Verification.create_session(Ecto.UUID.generate(), dcql_query())
    end

    test "returns :workspace_inactive when workspace is suspended" do
      %{workspace: ws} = create_workspace()

      {:ok, _} =
        ws |> Workspace.status_changeset("suspended") |> Repo.update()

      assert {:error, :workspace_inactive} = Verification.create_session(ws.id, dcql_query())
    end

    test "returns :workspace_inactive when workspace is deactivated" do
      %{workspace: ws} = create_workspace()

      {:ok, _} =
        ws |> Workspace.status_changeset("deactivated") |> Repo.update()

      assert {:error, :workspace_inactive} = Verification.create_session(ws.id, dcql_query())
    end

    test "returns :organization_inactive when organization is suspended" do
      %{workspace: ws, organization: org} = create_workspace()

      {:ok, _} =
        org |> Organization.status_changeset("suspended") |> Repo.update()

      assert {:error, :organization_inactive} = Verification.create_session(ws.id, dcql_query())
    end

    test "also returns a pass-by-reference URI" do
      %{workspace: ws} = create_workspace()

      assert {:ok, %{authorization_request_uri_ref: ref_uri, session: s}} =
               Verification.create_session(ws.id, dcql_query())

      assert String.starts_with?(ref_uri, "openid4vp://")
      assert String.contains?(ref_uri, "request_uri=")
      assert String.contains?(ref_uri, URI.encode_www_form(s.id))
    end
  end

  describe "get_session/2" do
    test "returns the session when it belongs to the workspace" do
      %{workspace: ws} = create_workspace()
      {:ok, %{session: s}} = Verification.create_session(ws.id, dcql_query())
      assert {:ok, fetched} = Verification.get_session(ws.id, s.id)
      assert fetched.id == s.id
    end

    test "returns :session_not_found for cross-tenant lookup" do
      %{workspace: ws_a} = create_workspace()
      %{workspace: ws_b} = create_workspace()
      {:ok, %{session: s}} = Verification.create_session(ws_a.id, dcql_query())

      assert {:error, :session_not_found} = Verification.get_session(ws_b.id, s.id)
    end

    test "returns :workspace_inactive when workspace is suspended" do
      %{workspace: ws} = create_workspace()
      {:ok, %{session: s}} = Verification.create_session(ws.id, dcql_query())
      {:ok, _} = ws |> Workspace.status_changeset("suspended") |> Repo.update()

      assert {:error, :workspace_inactive} = Verification.get_session(ws.id, s.id)
    end

    test "returns :session_not_found for unknown id" do
      %{workspace: ws} = create_workspace()
      assert {:error, :session_not_found} = Verification.get_session(ws.id, Ecto.UUID.generate())
    end
  end

  describe "list_sessions/2" do
    test "lists workspace's sessions newest first" do
      %{workspace: ws} = create_workspace()
      {:ok, _} = Verification.create_session(ws.id, dcql_query())
      {:ok, _} = Verification.create_session(ws.id, dcql_query())

      assert {:ok, [s1, s2]} = Verification.list_sessions(ws.id)
      assert DateTime.compare(s1.inserted_at, s2.inserted_at) in [:gt, :eq]
    end

    test "doesn't leak sessions from other workspaces" do
      %{workspace: ws_a} = create_workspace()
      %{workspace: ws_b} = create_workspace()
      {:ok, _} = Verification.create_session(ws_a.id, dcql_query())

      assert {:ok, []} = Verification.list_sessions(ws_b.id)
    end

    test "filters by status" do
      %{workspace: ws} = create_workspace()
      {:ok, _} = Verification.create_session(ws.id, dcql_query())

      assert {:ok, [_]} = Verification.list_sessions(ws.id, status: "pending")
      assert {:ok, []} = Verification.list_sessions(ws.id, status: "completed")
    end

    test "honors limit and offset" do
      %{workspace: ws} = create_workspace()
      for _ <- 1..3, do: Verification.create_session(ws.id, dcql_query())

      assert {:ok, [_, _]} = Verification.list_sessions(ws.id, limit: 2)
      assert {:ok, [_]} = Verification.list_sessions(ws.id, limit: 1, offset: 2)
    end

    test "returns :workspace_inactive when workspace is suspended" do
      %{workspace: ws} = create_workspace()
      {:ok, _} = ws |> Workspace.status_changeset("suspended") |> Repo.update()
      assert {:error, :workspace_inactive} = Verification.list_sessions(ws.id)
    end
  end
end
