defmodule Sovra.Workspaces.WorkspaceProvisioningJobTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Accounts.User
  alias Sovra.Organizations.Organization
  alias Sovra.Webhooks.DeliveryJob
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace
  alias Sovra.Workspaces.WorkspaceProvisioningJob

  defp insert_pending_workspace(opts \\ []) do
    {:ok, user} =
      User.admin_changeset(%{
        email: "user-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Repo.insert()

    attrs =
      %{name: "Acme"}
      |> Map.merge(Map.new(Keyword.take(opts, [:webhook_url])))

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, attrs, user.id)
    ws
  end

  describe "perform/1" do
    test "happy path: generates keys, derives DID, marks done, emits webhook" do
      ws = insert_pending_workspace(webhook_url: "https://example.com/hook")

      assert :ok = perform_job(WorkspaceProvisioningJob, %{"workspace_id" => ws.id})

      done = Repo.reload!(ws)
      assert done.provisioning_status == "done"
      assert is_binary(done.signing_key_id)
      assert is_binary(done.eoa_key_id)
      assert String.starts_with?(done.eoa_address, "0x")
      assert done.did == "did:sovra:" <> done.eoa_address
      assert %DateTime{} = done.provisioned_at
      assert done.provisioning_error == nil

      assert_enqueued(
        worker: DeliveryJob,
        args: %{
          "event" => "identity.did-generated",
          "workspace_id" => ws.id,
          "payload" => %{
            "event" => "identity.did-generated",
            "workspace_id" => ws.id,
            "data" => %{"did" => done.did}
          }
        }
      )
    end

    test "skips webhook delivery work when the workspace has no webhook_url" do
      ws = insert_pending_workspace()
      assert ws.webhook_url == nil

      assert :ok = perform_job(WorkspaceProvisioningJob, %{"workspace_id" => ws.id})

      done = Repo.reload!(ws)
      assert done.provisioning_status == "done"

      # The webhook is still enqueued — the delivery job no-ops on its own.
      assert_enqueued(worker: DeliveryJob, args: %{"event" => "identity.did-generated"})
    end

    test "is idempotent when called against an already-done workspace" do
      ws = insert_pending_workspace()
      assert :ok = perform_job(WorkspaceProvisioningJob, %{"workspace_id" => ws.id})

      first = Repo.reload!(ws)
      Oban.drain_queue(queue: :provisioning, with_safety: false)

      assert :ok = perform_job(WorkspaceProvisioningJob, %{"workspace_id" => ws.id})

      second = Repo.reload!(ws)
      assert second.signing_key_id == first.signing_key_id
      assert second.eoa_address == first.eoa_address
      assert second.did == first.did
    end

    test "skips signing key regeneration when one is already persisted" do
      ws = insert_pending_workspace()

      {:ok, _} =
        ws
        |> Workspace.provisioning_progress_changeset(%{
          signing_key_id: "preexisting-key",
          signing_public_key_x: <<0::256>>,
          signing_public_key_y: <<0::256>>
        })
        |> Repo.update()

      assert :ok = perform_job(WorkspaceProvisioningJob, %{"workspace_id" => ws.id})

      done = Repo.reload!(ws)
      assert done.signing_key_id == "preexisting-key"
      assert done.provisioning_status == "done"
    end

    test "treats an already-registered DID as success (idempotent re-provision)" do
      ws = insert_pending_workspace()
      previous = Application.get_env(:sovra, :did_registry)

      try do
        Application.put_env(
          :sovra,
          :did_registry,
          SovraTest.Ethereum.AlreadyRegisteredDIDRegistry
        )

        assert :ok = perform_job(WorkspaceProvisioningJob, %{"workspace_id" => ws.id})
      after
        Application.put_env(:sovra, :did_registry, previous)
      end

      done = Repo.reload!(ws)
      assert done.provisioning_status == "done"
      assert done.provisioning_error == nil
      assert %DateTime{} = done.provisioned_at
    end

    test "cancels and writes failed state on the last attempt when chain fails" do
      ws = insert_pending_workspace()
      previous = Application.get_env(:sovra, :did_registry)

      try do
        Application.put_env(
          :sovra,
          :did_registry,
          SovraTest.Ethereum.AlwaysFailingDIDRegistry
        )

        assert {:cancel, _} =
                 perform_job(
                   WorkspaceProvisioningJob,
                   %{"workspace_id" => ws.id},
                   attempt: 5,
                   max_attempts: 5
                 )
      after
        Application.put_env(:sovra, :did_registry, previous)
      end

      failed = Repo.reload!(ws)
      assert failed.provisioning_status == "failed"
      assert is_binary(failed.provisioning_error)
    end

    test "retries (no terminal failure) on intermediate attempts" do
      ws = insert_pending_workspace()
      previous = Application.get_env(:sovra, :did_registry)

      try do
        Application.put_env(
          :sovra,
          :did_registry,
          SovraTest.Ethereum.AlwaysFailingDIDRegistry
        )

        assert {:error, _} =
                 perform_job(
                   WorkspaceProvisioningJob,
                   %{"workspace_id" => ws.id},
                   attempt: 1,
                   max_attempts: 5
                 )
      after
        Application.put_env(:sovra, :did_registry, previous)
      end

      partial = Repo.reload!(ws)
      assert partial.provisioning_status == "pending"
      assert partial.provisioning_error == nil
      # Earlier steps still committed for the next attempt to pick up.
      assert is_binary(partial.signing_key_id)
      assert String.starts_with?(partial.eoa_address, "0x")
      assert partial.did == "did:sovra:" <> partial.eoa_address
    end

    test "fails when ethereum config is missing entirely" do
      ws = insert_pending_workspace()
      previous = Application.get_env(:sovra, :ethereum)

      try do
        Application.put_env(:sovra, :ethereum, [])

        assert {:cancel, :ethereum_not_configured} =
                 perform_job(
                   WorkspaceProvisioningJob,
                   %{"workspace_id" => ws.id},
                   attempt: 5,
                   max_attempts: 5
                 )
      after
        Application.put_env(:sovra, :ethereum, previous)
      end

      failed = Repo.reload!(ws)
      assert failed.provisioning_status == "failed"
      assert failed.provisioning_error == "ethereum_not_configured"
    end

    test "cancels when the workspace doesn't exist" do
      assert {:cancel, :workspace_not_found} =
               perform_job(WorkspaceProvisioningJob, %{"workspace_id" => Ecto.UUID.generate()})
    end
  end
end
