defmodule Sovra.Issuer.CredentialStatusJob do
  @moduledoc """
  Writes a requested credential status change to the on-chain status list, then
  makes it the credential's `status` and sends its webhook:
  `credential.revoked`, `credential.suspended` or `credential.unsuspended`.

  Runs after the request rather than inside it, because the write waits for its
  receipt and on a public chain that can outlast the request. Until it lands the
  target is the credential's `pending_status`, and verifiers, which read the
  status list, still see the old status.

  Setting a bit that is already set, or clearing one that is already clear,
  does not revert, so a retry after a write that landed unrecorded just repeats
  it. The last failed attempt clears `pending_status`, records why in
  `status_change_error`, leaves `status` as it was, and sends
  `credential.status-change-failed`.
  """

  use Oban.Worker, queue: :chain, max_attempts: 5

  use Sovra.Log

  alias Sovra.Ethereum.ChainError
  alias Sovra.Ethereum.Client
  alias Sovra.Issuer.IssuedCredential
  alias Sovra.Repo
  alias Sovra.Webhooks
  alias Sovra.Workspaces.Workspace

  # Target status → the event that announces it, and the status-list write.
  @transitions %{
    "revoked" => {"credential.revoked", :revoke},
    "suspended" => {"credential.suspended", :suspend},
    "issued" => {"credential.unsuspended", :unsuspend}
  }

  @doc "The job that writes `credential`'s pending status change."
  def new_for(%IssuedCredential{id: id}), do: new(Log.job_args(%{credential_id: id}))

  @impl Oban.Worker
  def perform(
        %Oban.Job{
          args: %{"credential_id" => credential_id},
          attempt: attempt,
          max_attempts: max_attempts
        } = job
      ) do
    Log.adopt_job_context(job)

    case IssuedCredential |> Repo.get(credential_id) |> Repo.preload(:schema) do
      nil ->
        {:cancel, :credential_not_found}

      # Settled already, so there is nothing left to write.
      %IssuedCredential{pending_status: nil} ->
        :ok

      %IssuedCredential{pending_status: target} = credential ->
        Log.put_context(workspace_id: credential.issuer_id)
        {event, write} = Map.fetch!(@transitions, target)

        case write_status(credential, write) do
          {:ok, tx_hash} -> confirm(credential, event, tx_hash)
          {:error, reason} -> fail(credential, reason, attempt, max_attempts)
        end
    end
  end

  # With no chain configured there is no status list to write, and the change
  # applies as it is.
  defp write_status(credential, write) do
    if Client.configured?() do
      %Workspace{eoa_address: eoa_address} = Repo.get!(Workspace, credential.issuer_id)
      apply(revocation_registry(), write, [eoa_address, credential.status_list_index])
    else
      {:ok, nil}
    end
  end

  # The status and its webhook commit together, so an integrator is told about
  # exactly the state the credential is in.
  defp confirm(credential, event, tx_hash) do
    {:ok, updated} =
      Repo.transaction(fn ->
        updated =
          credential
          |> IssuedCredential.status_changeset(credential.pending_status)
          |> Repo.update!()

        {:ok, _jobs} =
          Webhooks.enqueue(credential.issuer_id, event, %{
            "credential_id" => updated.id,
            "holder_did" => updated.holder_did,
            "schema_type" => credential.schema.credential_type,
            "status_at" => DateTime.utc_now() |> DateTime.to_iso8601()
          })

        updated
      end)

    # `event` is the webhook's event name, so the log and the webhook carry the
    # same vocabulary. Revocation is the mutation with legal weight and the one
    # most likely to be disputed; tx_hash is what ties it to the on-chain status
    # list a third-party verifier reads. No `status`: the event name is the
    # outcome. previous_status is the half the name cannot carry — issued ->
    # revoked and suspended -> revoked are different stories.
    Log.event(:info, "credential status changed",
      event: event,
      credential_id: updated.id,
      workspace_id: updated.issuer_id,
      holder_did: updated.holder_did,
      previous_status: credential.status,
      status_list_index: updated.status_list_index,
      tx_hash: tx_hash
    )

    :ok
  end

  # `final` tells "will retry" from "gave up", and only the final attempt
  # changes what the credential says.
  defp fail(credential, reason, attempt, max_attempts) do
    final? = attempt >= max_attempts

    Log.event(:error, "credential status change failed",
      event: "credential.status_change.failed",
      credential_id: credential.id,
      workspace_id: credential.issuer_id,
      status: credential.pending_status,
      reason: Log.reason(reason),
      attempt: attempt,
      final: final?
    )

    if final? do
      {:ok, _} =
        Repo.transaction(fn ->
          credential
          |> IssuedCredential.status_change_failed_changeset(ChainError.message(reason))
          |> Repo.update!()

          {:ok, _jobs} =
            Webhooks.enqueue(credential.issuer_id, "credential.status-change-failed", %{
              "credential_id" => credential.id,
              "holder_did" => credential.holder_did,
              "schema_type" => credential.schema.credential_type,
              "requested_status" => credential.pending_status,
              "status" => credential.status,
              "status_at" => DateTime.utc_now() |> DateTime.to_iso8601()
            })
        end)

      {:cancel, reason}
    else
      {:error, reason}
    end
  end

  defp revocation_registry,
    do: Application.get_env(:sovra, :revocation_registry, Sovra.Ethereum.RevocationRegistry)
end
