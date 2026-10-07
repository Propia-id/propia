defmodule Sovra.Issuer.CredentialStatusJobTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Issuer
  alias Sovra.Issuer.CredentialStatusJob
  alias Sovra.Issuer.IssuedCredential
  alias Sovra.Webhooks.DeliveryJob

  setup do
    workspace =
      provision_workspace(fixture_workspace(webhook_url: "https://example.com/hook").workspace)

    {:ok, schema} =
      Issuer.create_schema(workspace.id, %{
        schema_id: "s-#{System.unique_integer([:positive])}",
        credential_type: "TestCredential",
        name: "Test",
        validity_period: "1y",
        claims: [%{"key" => "name", "type" => "string", "required" => true}]
      })

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {:ok, credential} =
      %{
        issuer_id: workspace.id,
        schema_id: schema.id,
        holder_did: "did:sovra:0xholder",
        status_list_index: 7,
        issued_at: now,
        expires_at: DateTime.add(now, 86_400, :second)
      }
      |> IssuedCredential.create_changeset()
      |> Repo.insert()

    %{workspace: workspace, credential: credential}
  end

  defp args(credential), do: %{"credential_id" => credential.id}

  defp with_registry(module, fun) do
    previous = Application.get_env(:sovra, :revocation_registry)
    Application.put_env(:sovra, :revocation_registry, module)

    try do
      fun.()
    after
      Application.put_env(:sovra, :revocation_registry, previous)
    end
  end

  defp webhooks(event) do
    all_enqueued(worker: DeliveryJob)
    |> Enum.filter(&(&1.args["event"] == event))
    |> Enum.map(& &1.args["payload"]["data"])
  end

  describe "requesting a change" do
    test "sets the target as pending and queues the write, leaving the status", %{
      workspace: ws,
      credential: cred
    } do
      assert {:ok, requested} = Issuer.revoke_credential(ws.id, cred.id)

      assert requested.status == "issued"
      assert requested.pending_status == "revoked"
      assert Repo.reload!(cred).pending_status == "revoked"
      assert_enqueued(worker: CredentialStatusJob, args: args(cred), queue: :chain)
      assert webhooks("credential.revoked") == []
    end

    test "refuses another change while one is on the way", %{workspace: ws, credential: cred} do
      {:ok, _} = Issuer.suspend_credential(ws.id, cred.id)

      assert {:error, :status_change_pending} = Issuer.revoke_credential(ws.id, cred.id)
    end
  end

  describe "perform/1" do
    test "confirms a revocation and announces it", %{workspace: ws, credential: cred} do
      {:ok, _} = Issuer.revoke_credential(ws.id, cred.id)

      assert :ok = perform_job(CredentialStatusJob, args(cred))

      revoked = Repo.reload!(cred)
      assert revoked.status == "revoked"
      assert revoked.pending_status == nil

      assert [%{"credential_id" => id, "holder_did" => "did:sovra:0xholder"}] =
               webhooks("credential.revoked")

      assert id == cred.id
    end

    test "an unsuspend lands as issued, announced as unsuspended", %{
      workspace: ws,
      credential: cred
    } do
      {:ok, _} = Issuer.suspend_credential(ws.id, cred.id)
      assert :ok = perform_job(CredentialStatusJob, args(cred))
      {:ok, _} = Issuer.unsuspend_credential(ws.id, cred.id)
      assert :ok = perform_job(CredentialStatusJob, args(cred))

      assert Repo.reload!(cred).status == "issued"
      assert [_] = webhooks("credential.unsuspended")
    end

    test "keeps the change pending on an attempt that will be retried", %{
      workspace: ws,
      credential: cred
    } do
      {:ok, _} = Issuer.revoke_credential(ws.id, cred.id)

      with_registry(SovraTest.Ethereum.AlwaysFailingRevocationRegistry, fn ->
        assert {:error, :rpc_down} =
                 perform_job(CredentialStatusJob, args(cred), attempt: 1, max_attempts: 5)
      end)

      pending = Repo.reload!(cred)
      assert pending.status == "issued"
      assert pending.pending_status == "revoked"
      assert webhooks("credential.status-change-failed") == []
    end

    test "drops the change on the last attempt, keeps the status, and announces it", %{
      workspace: ws,
      credential: cred
    } do
      {:ok, _} = Issuer.revoke_credential(ws.id, cred.id)

      with_registry(SovraTest.Ethereum.AlwaysFailingRevocationRegistry, fn ->
        assert {:cancel, :rpc_down} =
                 perform_job(CredentialStatusJob, args(cred), attempt: 5, max_attempts: 5)
      end)

      failed = Repo.reload!(cred)
      assert failed.status == "issued"
      assert failed.pending_status == nil
      assert failed.status_change_error == "rpc_down"

      assert [%{"requested_status" => "revoked", "status" => "issued"}] =
               webhooks("credential.status-change-failed")

      assert webhooks("credential.revoked") == []

      # And the credential can be asked again, which clears the error.
      assert {:ok, %{pending_status: "revoked", status_change_error: nil}} =
               Issuer.revoke_credential(ws.id, cred.id)
    end

    test "does nothing when no change is pending", %{credential: cred} do
      assert :ok = perform_job(CredentialStatusJob, args(cred))
      assert Repo.reload!(cred).status == "issued"
    end

    test "cancels when the credential does not exist" do
      assert {:cancel, :credential_not_found} =
               perform_job(CredentialStatusJob, %{"credential_id" => Ecto.UUID.generate()})
    end
  end
end
