defmodule Sovra.AuditEventsTest do
  @moduledoc """
  The access-granting audit trail: who could issue credentials, when, and where
  a workspace's event stream points. None of this was recorded before.
  """

  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  import Sovra.LogHelpers

  alias Sovra.Auth.ArgsCrypto
  alias Sovra.Auth.IssuerInvitations
  alias Sovra.Auth.MailerJob
  alias Sovra.Organizations
  alias Sovra.Webhooks
  alias Sovra.Workspaces
  alias Sovra.Workspaces.ApiKeys

  describe "organizations" do
    test "org.created carries the founding owner" do
      user = fixture_user()

      {{:ok, %{organization: org}}, events} =
        capture_events(fn ->
          Organizations.create_organization(user.id, %{
            name: "Ministry #{System.unique_integer()}"
          })
        end)

      assert_event(events, "org.created", org_id: org.id, owner_user_id: user.id)
    end

    test "org.deactivated records the status it came from" do
      %{org: org} = fixture_workspace()

      {{:ok, _}, events} =
        capture_events(fn -> Organizations.deactivate_organization(org) end)

      assert_event(events, "org.deactivated", org_id: org.id, previous_status: "active")
    end

    test "org.member.added records the granted role" do
      %{org: org} = fixture_workspace()
      user = fixture_user()

      {{:ok, _}, events} =
        capture_events(fn -> Organizations.add_member(org.id, user.id, "admin") end)

      assert_event(events, "org.member.added",
        org_id: org.id,
        member_user_id: user.id,
        member_role: "admin"
      )
    end
  end

  describe "workspaces" do
    test "workspace.created records the owner" do
      owner = fixture_user()
      org = fixture_org()

      {{:ok, %{workspace: ws}}, events} =
        capture_events(fn -> Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id) end)

      assert_event(events, "workspace.created",
        workspace_id: ws.id,
        org_id: org.id,
        owner_user_id: owner.id
      )
    end
  end

  describe "webhooks" do
    # A webhook URL routinely carries a shared secret in its path or query, and
    # these logs leave the host for New Relic. The host answers the question
    # the events exist for — where the event stream goes — and
    # workspace_webhooks.url has the rest for anyone with database access.
    test "workspace.webhook.created records the host and events, never the full URL" do
      %{workspace: ws} = fixture_workspace()

      {{:ok, %{webhook: webhook, secret: secret}}, events} =
        capture_events(fn ->
          Webhooks.create_webhook(ws.id, %{
            url: "https://acme.example.com/hook?token=s3cr3t",
            events: ["credential.issued", "credential.revoked"]
          })
        end)

      event =
        assert_event(events, "workspace.webhook.created",
          workspace_id: ws.id,
          webhook_id: webhook.id,
          webhook_host: "acme.example.com",
          events: "credential.issued,credential.revoked",
          enabled: true
        )

      refute inspect(event.metadata) =~ "s3cr3t"
      refute inspect(event.metadata) =~ "/hook"
      refute inspect(event.metadata) =~ secret
    end

    test "workspace.webhook.updated records both hosts, never the full URL" do
      %{workspace: ws} = fixture_workspace()
      %{webhook: webhook} = fixture_webhook(ws, url: "https://old.example.com/hook")

      {{:ok, _}, events} =
        capture_events(fn ->
          Webhooks.update_webhook(ws.id, webhook.id, %{
            url: "https://new.example.com/hook?token=s3cr3t",
            enabled: false
          })
        end)

      event =
        assert_event(events, "workspace.webhook.updated",
          workspace_id: ws.id,
          webhook_id: webhook.id,
          previous_webhook_host: "old.example.com",
          webhook_host: "new.example.com",
          enabled: false
        )

      refute inspect(event.metadata) =~ "s3cr3t"
      refute inspect(event.metadata) =~ "/hook"
    end

    test "an update that changes nothing emits nothing" do
      %{workspace: ws} = fixture_workspace()
      %{webhook: webhook} = fixture_webhook(ws)

      {{:ok, _}, events} =
        capture_events(fn ->
          Webhooks.update_webhook(ws.id, webhook.id, %{url: webhook.url})
        end)

      refute_event(events, "workspace.webhook.updated")
    end

    test "workspace.webhook.deleted fires on deletion" do
      %{workspace: ws} = fixture_workspace()
      %{webhook: webhook} = fixture_webhook(ws, url: "https://gone.example.com/hook")

      {{:ok, _}, events} =
        capture_events(fn -> Webhooks.delete_webhook(ws.id, webhook.id) end)

      assert_event(events, "workspace.webhook.deleted",
        workspace_id: ws.id,
        webhook_id: webhook.id,
        webhook_host: "gone.example.com"
      )
    end

    test "workspace.webhook.secret_rotated fires on rotation" do
      %{workspace: ws} = fixture_workspace()
      %{webhook: webhook} = fixture_webhook(ws)

      {{:ok, %{secret: secret}}, events} =
        capture_events(fn -> Webhooks.rotate_webhook_secret(ws.id, webhook.id) end)

      event =
        assert_event(events, "workspace.webhook.secret_rotated",
          workspace_id: ws.id,
          webhook_id: webhook.id
        )

      # The point of the event is that the secret rotated, never the secret.
      refute inspect(event.metadata) =~ secret
    end
  end

  describe "workspace membership" do
    setup do
      %{workspace: ws, owner: owner} = fixture_workspace()
      member = fixture_user()
      {:ok, _} = Workspaces.add_member(ws.id, member.id, "member")
      %{workspace: ws, owner: owner, member: member}
    end

    test "member.added records the role", %{workspace: ws} do
      newcomer = fixture_user()

      {{:ok, _}, events} =
        capture_events(fn -> Workspaces.add_member(ws.id, newcomer.id, "admin") end)

      assert_event(events, "workspace.member.added",
        workspace_id: ws.id,
        member_user_id: newcomer.id,
        member_role: "admin"
      )
    end

    test "member.role_changed records both roles", %{workspace: ws, member: member} do
      {{:ok, _}, events} =
        capture_events(fn -> Workspaces.update_member_role(ws.id, member.id, "admin") end)

      assert_event(events, "workspace.member.role_changed",
        workspace_id: ws.id,
        member_user_id: member.id,
        previous_role: "member",
        member_role: "admin"
      )
    end

    test "member.removed records the role that was lost", %{workspace: ws, member: member} do
      {{:ok, _}, events} =
        capture_events(fn -> Workspaces.remove_member(ws.id, member.id) end)

      assert_event(events, "workspace.member.removed",
        workspace_id: ws.id,
        member_user_id: member.id,
        previous_role: "member"
      )
    end

    test "the last-admin guard is logged, not silently swallowed", %{
      workspace: ws,
      owner: owner
    } do
      # Demoting the only admin would lock the workspace out of its own
      # administration. From the UI this looks like the change just failed.
      {{:error, :last_admin}, events} =
        capture_events(fn -> Workspaces.update_member_role(ws.id, owner.id, "member") end)

      assert_event(events, "workspace.member.change_rejected",
        workspace_id: ws.id,
        member_user_id: owner.id,
        change: :role_change,
        reason: :last_admin
      )

      {{:error, :last_admin}, events} =
        capture_events(fn -> Workspaces.remove_member(ws.id, owner.id) end)

      assert_event(events, "workspace.member.change_rejected",
        change: :removal,
        reason: :last_admin
      )
    end

    test "acting on a non-member is logged with its own reason", %{workspace: ws} do
      stranger = fixture_user()

      {{:error, :not_a_member}, events} =
        capture_events(fn -> Workspaces.remove_member(ws.id, stranger.id) end)

      assert_event(events, "workspace.member.change_rejected", reason: :not_a_member)
    end
  end

  describe "API keys" do
    test "created and revoked, with the name but never the key" do
      %{workspace: ws} = fixture_workspace()

      {{:ok, %{api_key: plaintext, record: record}}, events} =
        capture_events(fn -> ApiKeys.create_api_key(ws.id, "Production") end)

      event =
        assert_event(events, "workspace.api_key.created",
          workspace_id: ws.id,
          api_key_id: record.id,
          api_key_name: "Production"
        )

      refute inspect(event.metadata) =~ plaintext

      {{:ok, _}, events} = capture_events(fn -> ApiKeys.revoke_api_key(record) end)

      assert_event(events, "workspace.api_key.revoked",
        workspace_id: ws.id,
        api_key_id: record.id
      )
    end
  end

  describe "invitations" do
    test "created, code requested, and revoked — addresses only as fingerprints" do
      Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
      on_exit(fn -> Application.delete_env(:sovra, :log_fingerprint_key) end)

      admin = fixture_user()
      email = "invitee-#{System.unique_integer([:positive])}@example.gov"

      {{:ok, invitation}, events} =
        capture_events(fn -> IssuerInvitations.create(email, admin.id) end)

      event =
        assert_event(events, "invitation.created",
          invitation_id: invitation.id,
          invited_by: admin.id,
          email_domain: "example.gov"
        )

      assert event.metadata[:email_fp] == Sovra.Log.fingerprint(email)
      refute inspect(event.metadata) =~ "invitee-"

      token = latest_secret("issuer_invitation", "encrypted_token")

      {{:ok, _}, events} =
        capture_events(fn -> IssuerInvitations.request_code(token) end)

      assert_event(events, "invitation.code_requested", invitation_id: invitation.id)

      {{:ok, _}, events} = capture_events(fn -> IssuerInvitations.revoke(invitation.id) end)

      assert_event(events, "invitation.revoked", invitation_id: invitation.id)
    end

    test "a wrong code is rejected with its own reason" do
      admin = fixture_user()
      email = "invitee-#{System.unique_integer([:positive])}@example.gov"
      {:ok, _invitation} = IssuerInvitations.create(email, admin.id)
      token = latest_secret("issuer_invitation", "encrypted_token")
      {:ok, _} = IssuerInvitations.request_code(token)

      {{:error, :invalid_code}, events} =
        capture_events(fn ->
          IssuerInvitations.accept(token, "000000", %{
            full_name: "Test User",
            organization_name: "Test Org",
            password: "a-very-strong-password-123"
          })
        end)

      assert_event(events, "invitation.rejected", reason: :invalid_code)
    end

    test "a rejection carrying a changeset logs field names, not submitted values" do
      # claim_and_register/2 returns the registration changeset, whose changes
      # hold the email and full name. Log.reason/1 is what keeps them out.
      admin = fixture_user()
      email = "invitee-#{System.unique_integer([:positive])}@example.gov"
      {:ok, _invitation} = IssuerInvitations.create(email, admin.id)
      token = latest_secret("issuer_invitation", "encrypted_token")
      {:ok, _} = IssuerInvitations.request_code(token)
      code = latest_secret("issuer_invitation_code", "encrypted_code")

      {_, events} =
        capture_events(fn ->
          IssuerInvitations.accept(token, code, %{
            full_name: "Test User",
            organization_name: "Test Org",
            password: "short"
          })
        end)

      event = assert_event(events, "invitation.rejected")
      assert event.metadata[:reason] =~ "password"
      refute inspect(event.metadata) =~ "Test User"
      refute inspect(event.metadata) =~ "invitee-"
    end
  end

  # The plaintext token and code are never returned — they go out by email — so
  # recover them the way the invitee does, from the mail we just enqueued.
  defp latest_secret(kind, key) do
    %{args: args} =
      all_enqueued(worker: MailerJob)
      |> Enum.filter(&(&1.args["kind"] == kind))
      |> Enum.max_by(& &1.id)

    {:ok, plaintext} = ArgsCrypto.decrypt(args[key])
    plaintext
  end
end
