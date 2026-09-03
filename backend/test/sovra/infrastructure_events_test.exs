defmodule Sovra.InfrastructureEventsTest do
  @moduledoc """
  On-chain writes, async jobs, and the two service boundaries.

  The headline property: every chain event carries an `op` label. Before this,
  a failing transaction was a bare `"Transaction failed: …"` and the
  `relayer_tx_failed` alert could not tell a DID registration from a revocation
  sync from a document anchoring — the alert fired and said nothing useful.
  """

  use Sovra.DataCase, async: false

  import Sovra.LogHelpers

  alias Sovra.Webhooks
  alias Sovra.Workspaces.WorkspaceProvisioningJob

  describe "chain transactions carry an op label" do
    test "a send failure names the operation and its subject" do
      # Nothing is listening on the configured RPC in test, so this fails at
      # the transport — the path that used to log a bare "Transaction failed:"
      # with no operation, no workspace and no subject, leaving the
      # relayer_tx_failed alert unable to say what broke.
      #
      # Called through the real registry module so the op label is exercised
      # where it is actually written, not handed in by the test. The DID
      # registry is the one with an address configured in test.
      eoa = "0x" <> String.duplicate("ab", 20)
      key = :crypto.strong_rand_bytes(32)

      {{:error, _}, events} =
        capture_events(fn ->
          Sovra.Ethereum.DIDRegistry.register_issuer_did(eoa, key, key, "https://example.test")
        end)

      event = assert_event(events, "chain.tx.send_failed", op: :did_register)

      assert event.level == :error
      assert event.metadata[:subject_id] == eoa
      assert event.metadata[:reason]
    end
  end

  describe "workspace provisioning" do
    test "every step is named on the way through" do
      %{workspace: ws} = fixture_workspace()

      {_result, events} =
        capture_events(fn ->
          Oban.drain_queue(queue: :provisioning, with_safety: false)
        end)

      for step <- [:signing_key, :eoa, :did, :chain_registration] do
        assert_event(events, "workspace.provisioning.step_completed",
          workspace_id: ws.id,
          step: step
        )
      end

      completed = assert_event(events, "workspace.provisioning.completed", workspace_id: ws.id)
      assert completed.metadata[:did]
      assert completed.metadata[:eoa_address]
    end

    test "a failing step is named, and says whether it will be retried" do
      # The pre-existing Oban alert says a provisioning job failed; only this
      # says which of the four steps, and the steps are partly irreversible —
      # a KMS signing key exists before the EOA does.
      Application.put_env(:sovra, :did_registry, SovraTest.Ethereum.AlwaysFailingDIDRegistry)

      on_exit(fn ->
        Application.put_env(:sovra, :did_registry, SovraTest.Ethereum.StubDIDRegistry)
      end)

      %{workspace: ws} = fixture_workspace()

      {_, events} =
        capture_events(fn ->
          Oban.drain_queue(queue: :provisioning, with_safety: false)
        end)

      failed =
        assert_event(events, "workspace.provisioning.step_failed",
          workspace_id: ws.id,
          step: :chain_registration,
          reason: :rpc_down
        )

      assert failed.level == :error
      assert failed.metadata[:attempt] == 1
      assert failed.metadata[:max_attempts] == 5
      # `final` is what separates "will retry" from "gave up".
      assert failed.metadata[:final] == false
      refute_event(events, "workspace.provisioning.completed")
    end

    test "the final attempt is marked, and the workspace is marked failed" do
      Application.put_env(:sovra, :did_registry, SovraTest.Ethereum.AlwaysFailingDIDRegistry)

      on_exit(fn ->
        Application.put_env(:sovra, :did_registry, SovraTest.Ethereum.StubDIDRegistry)
      end)

      %{workspace: ws} = fixture_workspace()

      {_, events} =
        capture_events(fn ->
          WorkspaceProvisioningJob.perform(%Oban.Job{
            id: 1,
            attempt: 5,
            max_attempts: 5,
            args: %{"workspace_id" => ws.id}
          })
        end)

      assert_event(events, "workspace.provisioning.step_failed",
        workspace_id: ws.id,
        step: :chain_registration,
        final: true
      )

      assert Sovra.Repo.reload!(ws).provisioning_status == "failed"
    end

    test "a retry does not re-announce the steps it skipped" do
      Application.put_env(:sovra, :did_registry, SovraTest.Ethereum.AlwaysFailingDIDRegistry)

      on_exit(fn ->
        Application.put_env(:sovra, :did_registry, SovraTest.Ethereum.StubDIDRegistry)
      end)

      %{workspace: ws} = fixture_workspace()
      Oban.drain_queue(queue: :provisioning, with_safety: false)

      # Second attempt: the key, EOA and DID already exist, so those steps
      # return early and stay quiet. Only the chain registration is retried.
      {_, events} =
        capture_events(fn ->
          WorkspaceProvisioningJob.perform(%Oban.Job{
            id: 2,
            attempt: 2,
            max_attempts: 5,
            args: %{"workspace_id" => ws.id}
          })
        end)

      for step <- [:signing_key, :eoa, :did] do
        refute Enum.any?(events, fn e ->
                 e.metadata[:event] == "workspace.provisioning.step_completed" and
                   e.metadata[:step] == step
               end),
               "step #{step} was re-announced on a retry"
      end

      assert_event(events, "workspace.provisioning.step_failed", step: :chain_registration)
    end
  end

  describe "webhooks" do
    test "the delivery_id is recorded at enqueue, which is what a ticket quotes" do
      %{workspace: ws} = fixture_workspace(webhook_url: "https://example.com/hook")

      {{:ok, job}, events} =
        capture_events(fn ->
          Webhooks.enqueue(ws.id, "credential.issued", %{"credential_id" => "abc"})
        end)

      delivery_id = enqueued(job).args["delivery_id"]
      assert delivery_id == enqueued(job).args["payload"]["id"]

      assert_event(events, "webhook.enqueued",
        delivery_id: delivery_id,
        workspace_id: ws.id,
        event_type: "credential.issued"
      )
    end

    test "a workspace with no destination is a recorded no-op, not a failure" do
      %{workspace: ws} = fixture_workspace()
      {:ok, job} = Webhooks.enqueue(ws.id, "credential.issued", %{})

      {result, events} =
        capture_events(fn -> Sovra.Webhooks.DeliveryJob.perform(enqueued(job)) end)

      assert result == :ok
      assert_event(events, "webhook.skipped", reason: :no_webhook_url)
    end

    test "delivery outcomes are separated into delivered, discarded and retried" do
      %{workspace: ws} = fixture_workspace(webhook_url: "https://example.com/hook")

      for {status, event, level} <- [
            {200, "webhook.delivered", :info},
            {404, "webhook.discarded", :warning},
            {503, "webhook.failed", :warning}
          ] do
        {:ok, job} = Webhooks.enqueue(ws.id, "credential.issued", %{})

        Application.put_env(:sovra, :webhook_req_opts,
          plug: fn conn -> Plug.Conn.send_resp(conn, status, "") end
        )

        {_result, events} =
          capture_events(fn -> Sovra.Webhooks.DeliveryJob.perform(enqueued(job)) end)

        found = assert_event(events, event, status: status)
        assert found.level == level
        assert is_integer(found.metadata[:duration_ms])
      end
    after
      Application.delete_env(:sovra, :webhook_req_opts)
    end
  end

  # Oban.insert/1 hands back the job with args exactly as given — atom keys —
  # while a worker only ever sees them after a JSON round-trip through the
  # database. Reload so perform/1 gets the shape production gives it.
  defp enqueued(%Oban.Job{id: id}), do: Sovra.Repo.get!(Oban.Job, id)

  describe "the signer boundary" do
    test "an unreachable signer is an error on the API side, not just the signer's" do
      previous = Application.get_env(:sovra, :signer)

      Application.put_env(:sovra, :signer,
        url: "http://127.0.0.1:1",
        token: "t",
        req_options: [retry: false]
      )

      on_exit(fn -> Application.put_env(:sovra, :signer, previous) end)

      {{:error, _}, events} =
        capture_events(fn -> Sovra.Signer.Client.get("/v1/relayer/address") end)

      event = assert_event(events, "signer.unreachable", path: "/v1/relayer/address")
      assert event.level == :error
    end

    test "a missing configuration is distinguishable from an unreachable host" do
      previous = Application.get_env(:sovra, :signer)
      Application.delete_env(:sovra, :signer)
      on_exit(fn -> Application.put_env(:sovra, :signer, previous) end)

      {{:error, :signer_url_missing}, events} =
        capture_events(fn -> Sovra.Signer.Client.get("/v1/relayer/address") end)

      assert_event(events, "signer.misconfigured", reason: :signer_url_missing)
    end
  end

  describe "documents" do
    test "a visibility change to public is recorded with both values" do
      %{workspace: ws} = provision_and_workspace()
      document = insert_document(ws)

      {{:ok, _}, events} =
        capture_events(fn -> Sovra.Documents.set_visibility(ws.id, document.id, "public") end)

      # `public` means holding the id is the whole authorization.
      assert_event(events, "document.visibility.changed",
        document_id: document.id,
        workspace_id: ws.id,
        previous_visibility: "private",
        visibility: "public"
      )
    end

    defp provision_and_workspace do
      %{workspace: ws} = fixture_workspace()
      %{workspace: provision_workspace(ws)}
    end

    defp insert_document(ws) do
      {:ok, schema} =
        Sovra.Issuer.create_schema(ws.id, %{
          schema_id: "doc-#{System.unique_integer([:positive])}",
          credential_type: "Attestation",
          name: "Attestation",
          kind: "document",
          claims: [
            %{"key" => "subject", "type" => "string", "required" => true, "disclosable" => false}
          ]
        })

      {:ok, document} =
        Sovra.Documents.SignedDocument.create_changeset(%{
          id: Ecto.UUID.generate(),
          workspace_id: ws.id,
          schema_id: schema.id,
          credential: "header.payload.sig",
          digest: :crypto.hash(:sha256, "x"),
          status: "signed",
          visibility: "private",
          signed_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })
        |> Sovra.Repo.insert()

      document
    end
  end

  describe "email outcomes" do
    test "a sent email records the kind and never the address" do
      Application.put_env(:sovra, :log_fingerprint_key, "test-fingerprint-key")
      on_exit(fn -> Application.delete_env(:sovra, :log_fingerprint_key) end)

      email = "mailer-#{System.unique_integer([:positive])}@example.gov"

      {:ok, _} =
        Sovra.Accounts.register_user(%{
          email: email,
          password: "a-very-strong-password-123",
          full_name: "Ada Lovelace",
          workspace_name: "Registry"
        })

      {_, events} =
        capture_events(fn -> Oban.drain_queue(queue: :mailers, with_safety: false) end)

      event = assert_event(events, "email.sent", kind: "welcome")

      # A user-scoped mail is correlated by user_id; only the invitation kinds,
      # which are sent before an account exists, carry an email fingerprint.
      # Either way the address itself must never appear.
      assert event.metadata[:user_id]
      refute Map.has_key?(event.metadata, :email_fp)
      refute inspect(event.metadata) =~ "mailer-"
      refute inspect(event.metadata) =~ email
    end
  end
end
