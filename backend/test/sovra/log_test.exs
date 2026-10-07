defmodule Sovra.LogTest do
  use ExUnit.Case, async: true

  import Sovra.LogHelpers

  require Sovra.Log
  alias Sovra.Log

  describe "the event catalogue" do
    # This list is FROZEN on purpose. Alert conditions in
    # infra/terraform/modules/newrelic_alerts/main.tf match on
    # `metadata.event`, so renaming or removing a name here disarms an alert
    # with no other symptom — a silent loss of production coverage.
    #
    # When this test fails, the fix is not to update the list on its own:
    # update the Terraform conditions that reference the old name in the same
    # commit. See docs/plans/backend-logging.md.
    @frozen [
      "admin.issuer_account.created",
      "app.boot",
      "auth.api_key.rejected",
      "auth.logged_out",
      "auth.login.failed",
      "auth.login.succeeded",
      "auth.origin.rejected",
      "auth.password_reset.completed",
      "auth.password_reset.rejected",
      "auth.password_reset.requested",
      "auth.rate_limit.denied",
      "auth.refresh_token.reuse_detected",
      "auth.registered",
      "auth.registration.rejected",
      "auth.session.refresh_rejected",
      "auth.session.refreshed",
      "auth.session.rejected",
      "authz.denied",
      "credential.issuance.errored",
      "credential.design.deleted",
      "credential.design.updated",
      "credential.issued",
      "credential.offer.code_regenerated",
      "credential.offer.created",
      "credential.request.rejected",
      "credential.revoked",
      "credential.schema.chain_registered",
      "credential.schema.chain_registration_failed",
      "credential.schema.created",
      "credential.schema.deleted",
      "credential.schema.rejected",
      "credential.schema.revised",
      "credential.status_change.failed",
      "credential.status_change.rejected",
      "credential.status_change.requested",
      "credential.suspended",
      "credential.token.exchanged",
      "credential.unsuspended",
      "chain.tx.confirmed",
      "chain.tx.receipt_timeout",
      "chain.tx.receipt_unexpected",
      "chain.tx.reverted",
      "chain.tx.send_failed",
      "chain.tx.submitted",
      "did.resolution.failed",
      "document.anchored",
      "document.anchoring_failed",
      "document.rejected",
      "document.signed",
      "document.visibility.changed",
      "email.enqueue_failed",
      "email.failed",
      "email.sent",
      "signer.misconfigured",
      "signer.request.failed",
      "signer.response.errored",
      "signer.unreachable",
      "webhook.delivered",
      "webhook.discarded",
      "webhook.enqueue_failed",
      "webhook.enqueued",
      "webhook.failed",
      "webhook.skipped",
      "workspace.provisioning.completed",
      "workspace.provisioning.step_completed",
      "workspace.provisioning.step_failed",
      "issuance.status_index.exhausted",
      "issuance.status_index.widened",
      "guardian.auth.rejected",
      "guardian.authenticated",
      "guardian.oauth.authenticated",
      "guardian.oauth.rejected",
      "guardian.oauth_binding.mismatch",
      "guardian.onboard.rejected",
      "guardian.onboarded",
      "guardian.recovery.errored",
      "guardian.recovery.finalized",
      "guardian.recovery.initiated",
      "guardian.recovery.rejected",
      "guardian.recovery_key.rotation_confirmed",
      "guardian.recovery_key.rotation_failed",
      "guardian.recovery_key.rotation_started",
      "health.check.failed",
      "http.request",
      "invitation.accepted",
      "invitation.code_requested",
      "invitation.created",
      "invitation.rejected",
      "invitation.revoked",
      "issuance.tx_code.locked_out",
      "presentation.failed",
      "presentation.received",
      "presentation.rejected",
      "presentation.request.created",
      "presentation.request.expired",
      "presentation.request.fetched",
      "presentation.request.rejected",
      "presentation.verified",
      "org.created",
      "org.deactivated",
      "org.member.added",
      "workspace.api_key.created",
      "workspace.api_key.revoked",
      "workspace.created",
      "workspace.member.added",
      "workspace.member.change_rejected",
      "workspace.member.removed",
      "workspace.member.role_changed",
      "workspace.webhook_secret.regenerated",
      "workspace.webhook_url.changed"
    ]

    test "is exactly the frozen list" do
      assert Log.events() == Enum.sort(@frozen)
    end

    test "every name is dot-separated lowercase" do
      for name <- Log.events() do
        assert name =~ ~r/^[a-z0-9]+(\.[a-z0-9_-]+)+$/,
               "#{inspect(name)} does not match <domain>.<noun>.<verb>"
      end
    end
  end

  describe "event/3" do
    test "emits the message, level and metadata" do
      {_, events} =
        capture_events(fn ->
          Log.event(:error, "issuance blew up",
            event: "credential.issuance.errored",
            stage: "token",
            reason: "boom"
          )
        end)

      event = assert_event(events, "credential.issuance.errored", stage: "token")
      assert event.level == :error
      assert event.message == "issuance blew up"
      assert event.metadata[:reason] == "boom"
    end

    test "reports the caller's source location, not Sovra.Log" do
      # event/3 is a macro so that New Relic's module.name / function.name /
      # line.number attributes point at the real call site.
      {_, events} =
        capture_events(fn ->
          Log.event(:info, "located", event: "credential.issuance.errored")
        end)

      event = assert_event(events, "credential.issuance.errored")
      assert {module, _fun, _arity} = event.metadata[:mfa]
      assert module == __MODULE__
    end

    test "drops nil and empty values instead of recording them" do
      {_, events} =
        capture_events(fn ->
          Log.event(:info, "sparse",
            event: "credential.issuance.errored",
            stage: nil,
            reason: ""
          )
        end)

      event = assert_event(events, "credential.issuance.errored")
      refute Map.has_key?(event.metadata, :stage)
      refute Map.has_key?(event.metadata, :reason)
    end

    test "rejects an unregistered event name" do
      assert_raise ArgumentError, ~r/unregistered log event/, fn ->
        Log.event(:info, "nope", event: "not.a.real.event")
      end
    end

    test "rejects a map, which New Relic would flatten into attributes" do
      # The failure mode this guards: a credential's claims reaching NRDB as
      # queryable attributes.
      assert_raise ArgumentError, ~r/is a map, which is not loggable/, fn ->
        Log.event(:info, "leak", event: "credential.issuance.errored", claims: %{"dni" => "123"})
      end
    end

    test "rejects a struct" do
      assert_raise ArgumentError, ~r/is a map, which is not loggable/, fn ->
        Log.event(:info, "leak",
          event: "credential.issuance.errored",
          offer: %Sovra.Issuer.CredentialOffer{}
        )
      end
    end

    test "rejects raw non-UTF-8 bytes, which are usually key material" do
      assert_raise ArgumentError, ~r/non-UTF-8 binary/, fn ->
        Log.event(:info, "leak", event: "credential.issuance.errored", key: <<0xFF, 0xFE>>)
      end
    end

    test "accepts scalars and date/time structs" do
      {_, events} =
        capture_events(fn ->
          Log.event(:info, "scalars",
            event: "credential.issuance.errored",
            count: 3,
            ratio: 1.5,
            ok?: true,
            stage: :token,
            at: ~U[2026-09-02 12:00:00Z]
          )
        end)

      event = assert_event(events, "credential.issuance.errored")
      assert event.metadata[:count] == 3
      assert event.metadata[:ratio] == 1.5
      assert event.metadata[:ok?] == true
      assert event.metadata[:stage] == :token
      assert event.metadata[:at] == ~U[2026-09-02 12:00:00Z]
    end
  end

  describe "reason/1" do
    test "passes atoms and binaries through" do
      assert Log.reason(:not_found) == :not_found
      assert Log.reason("boom") == "boom"
    end

    test "reduces a changeset to field names, never its submitted values" do
      changeset =
        %Sovra.Accounts.User{}
        |> Ecto.Changeset.cast(%{email: "leak@example.com", password: "short"}, [
          :email,
          :password
        ])
        |> Ecto.Changeset.validate_length(:password, min: 12)

      reason = Log.reason(changeset)

      assert reason == "invalid:password"
      refute reason =~ "leak@example.com"
      refute reason =~ "short"
    end

    test "unwraps a tagged tuple around a changeset" do
      changeset =
        %Sovra.Accounts.User{}
        |> Ecto.Changeset.cast(%{email: "leak@example.com"}, [:email])
        |> Ecto.Changeset.add_error(:email, "taken")

      assert Log.reason({:changeset, changeset}) == "changeset:invalid:email"
      refute Log.reason({:changeset, changeset}) =~ "leak@"
    end

    test "uses an exception's message" do
      assert Log.reason(%ArgumentError{message: "bad input"}) == "bad input"
    end

    test "names an unrecognized struct's type without its contents" do
      assert Log.reason(%Sovra.Issuer.CredentialOffer{c_nonce: "secret"}) ==
               "Sovra.Issuer.CredentialOffer"
    end

    test "never renders a bare map's contents" do
      assert Log.reason(%{"dni" => "12345678"}) == "map"
    end

    test "produces a value event/3 accepts" do
      changeset = Ecto.Changeset.change(%Sovra.Accounts.User{})

      {_, events} =
        capture_events(fn ->
          Log.event(:warning, "reduced",
            event: "credential.issuance.errored",
            reason: Log.reason({:changeset, changeset})
          )
        end)

      assert_event(events, "credential.issuance.errored")
    end
  end

  describe "put_context/1" do
    test "adds metadata carried by every later line in the process" do
      {_, events} =
        capture_events(fn ->
          Log.put_context(workspace_id: "ws-1", user_id: nil)
          Log.event(:info, "later", event: "credential.issuance.errored")
        end)

      event = assert_event(events, "credential.issuance.errored")
      assert event.metadata[:workspace_id] == "ws-1"
      refute Map.has_key?(event.metadata, :user_id)
    after
      Logger.reset_metadata()
    end
  end

  describe "job_args/1" do
    test "carries request_id across the Oban boundary" do
      Logger.metadata(request_id: "req-abc")
      assert Log.job_args(%{workspace_id: "ws-1"})[:request_id] == "req-abc"
    after
      Logger.reset_metadata()
    end

    test "is a no-op with no request in scope" do
      Logger.reset_metadata()
      assert Log.job_args(%{workspace_id: "ws-1"}) == %{workspace_id: "ws-1"}
    end
  end

  describe "sensitive keys" do
    test "become a fingerprint when a key is configured" do
      Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
      on_exit(fn -> Application.delete_env(:sovra, :log_fingerprint_key) end)

      {_, events} =
        capture_events(fn ->
          Log.event(:info, "sensitive",
            event: "credential.issuance.errored",
            email: "Someone@Example.GOV",
            ip: "203.0.113.7",
            oauth_subject: "google-user-123"
          )
        end)

      event = assert_event(events, "credential.issuance.errored")

      assert event.metadata[:email_fp] == Log.fingerprint("someone@example.gov")
      assert event.metadata[:ip_fp] == Log.fingerprint("203.0.113.7")
      assert event.metadata[:oauth_subject_fp] == Log.fingerprint("google-user-123")

      # The raw keys must be gone entirely, not merely emptied.
      for key <- [:email, :ip, :oauth_subject] do
        refute Map.has_key?(event.metadata, key)
      end

      refute inspect(event.metadata) =~ "Someone@Example.GOV"
      refute inspect(event.metadata) =~ "203.0.113.7"
      refute inspect(event.metadata) =~ "google-user-123"
    end

    test "fall back to the raw value under the un-suffixed name with no key" do
      Application.delete_env(:sovra, :log_fingerprint_key)

      {_, events} =
        capture_events(fn ->
          Log.event(:info, "sensitive",
            event: "credential.issuance.errored",
            email: "Someone@Example.GOV",
            ip: "203.0.113.7"
          )
        end)

      event = assert_event(events, "credential.issuance.errored")

      # Normalized, so the value matches what a fingerprint would have covered.
      assert event.metadata[:email] == "someone@example.gov"
      assert event.metadata[:ip] == "203.0.113.7"

      # The _fp names must NOT appear: the attribute name is what tells an
      # operator which of the two they are looking at, and
      # `metadata.email IS NOT NULL` is the detector for a keyless node.
      refute Map.has_key?(event.metadata, :email_fp)
      refute Map.has_key?(event.metadata, :ip_fp)
    end

    test "an email always contributes its domain, in the clear either way" do
      for key <- ["a-key", nil] do
        if key,
          do: Application.put_env(:sovra, :log_fingerprint_key, key),
          else: Application.delete_env(:sovra, :log_fingerprint_key)

        {_, events} =
          capture_events(fn ->
            Log.event(:info, "domain",
              event: "credential.issuance.errored",
              email: "someone@example.gov"
            )
          end)

        event = assert_event(events, "credential.issuance.errored")
        assert event.metadata[:email_domain] == "example.gov"
      end
    after
      Application.delete_env(:sovra, :log_fingerprint_key)
    end

    test "put_context/1 applies the same policy" do
      Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
      on_exit(fn -> Application.delete_env(:sovra, :log_fingerprint_key) end)

      {_, events} =
        capture_events(fn ->
          Log.put_context(email: "someone@example.gov")
          Log.event(:info, "from context", event: "credential.issuance.errored")
        end)

      event = assert_event(events, "credential.issuance.errored")
      assert event.metadata[:email_fp] == Log.fingerprint("someone@example.gov")
      refute Map.has_key?(event.metadata, :email)
    after
      Logger.reset_metadata()
    end

    test "a nil sensitive value contributes nothing either way" do
      {_, events} =
        capture_events(fn ->
          Log.event(:info, "absent", event: "credential.issuance.errored", email: nil)
        end)

      event = assert_event(events, "credential.issuance.errored")
      refute Map.has_key?(event.metadata, :email)
      refute Map.has_key?(event.metadata, :email_fp)
      refute Map.has_key?(event.metadata, :email_domain)
    end
  end

  describe "fingerprint/1" do
    setup do
      previous = Application.get_env(:sovra, :log_fingerprint_key)
      Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
      on_exit(fn -> Application.put_env(:sovra, :log_fingerprint_key, previous) end)
    end

    test "is stable, short, and normalizes case and whitespace" do
      fp = Log.fingerprint("Someone@Example.GOV")

      assert byte_size(fp) == 12
      assert fp =~ ~r/^[0-9a-f]{12}$/
      assert Log.fingerprint("  someone@example.gov  ") == fp
    end

    test "differs between addresses and does not contain the input" do
      fp = Log.fingerprint("someone@example.gov")

      refute fp == Log.fingerprint("someone.else@example.gov")
      refute fp =~ "example"
    end

    test "depends on the key" do
      fp = Log.fingerprint("someone@example.gov")
      Application.put_env(:sovra, :log_fingerprint_key, "a-different-key")

      refute Log.fingerprint("someone@example.gov") == fp
    end
  end

  describe "fingerprint/1 without a key" do
    test "returns nil so the attribute is simply omitted" do
      previous = Application.get_env(:sovra, :log_fingerprint_key)
      Application.delete_env(:sovra, :log_fingerprint_key)
      on_exit(fn -> Application.put_env(:sovra, :log_fingerprint_key, previous) end)

      assert Log.fingerprint("someone@example.gov") == nil
    end
  end

  describe "email_domain/1" do
    test "extracts and normalizes the domain" do
      assert Log.email_domain("Someone@Example.GOV") == "example.gov"
    end

    test "is nil for anything that is not an address" do
      assert Log.email_domain("not-an-address") == nil
      assert Log.email_domain("trailing@") == nil
      assert Log.email_domain(nil) == nil
    end
  end
end
