defmodule Sovra.Workspaces.WorkspaceProvisioningJob do
  @moduledoc """
  Async workspace provisioning. Generates the signing key and EOA, derives
  the workspace DID, registers the DID document on-chain, and emits an
  `identity.did-generated` webhook on success.

  Each step is gated on the workspace's current state so the job is safe to
  re-run after a partial earlier attempt — e.g. if signing key generation
  succeeded but chain registration failed, the next attempt picks up from
  the chain step without regenerating the key.

  Permanent failure (last Oban attempt) writes `provisioning_status =
  "failed"` and the error reason to `provisioning_error`. A retry endpoint
  resets the row to `pending` and re-enqueues a fresh job.
  """

  use Oban.Worker,
    queue: :provisioning,
    max_attempts: 5,
    unique: [
      keys: [:workspace_id],
      states: [:available, :scheduled, :executing, :retryable]
    ]

  use Sovra.Log

  alias Sovra.Crypto.Key
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Repo
  alias Sovra.Webhooks
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  @impl Oban.Worker
  def perform(
        %Oban.Job{
          args: %{"workspace_id" => workspace_id},
          attempt: attempt,
          max_attempts: max_attempts
        } = job
      ) do
    Log.adopt_job_context(job)
    Log.put_context(workspace_id: workspace_id)

    case Repo.get(Workspace, workspace_id) do
      nil ->
        {:cancel, :workspace_not_found}

      %Workspace{provisioning_status: "done"} ->
        :ok

      %Workspace{} = workspace ->
        run(workspace, attempt, max_attempts)
    end
  end

  # Each step is logged separately because they are only partly reversible: a
  # KMS signing key exists before the EOA does, and the EOA before the DID, so
  # "the job failed" is not enough to know what state the workspace is in. The
  # pre-existing Oban alert says a provisioning job failed; only these say
  # which step.
  defp run(workspace, attempt, max_attempts) do
    with {:ok, workspace} <- step(:signing_key, workspace, &ensure_signing_key/1),
         {:ok, workspace} <- step(:eoa, workspace, &ensure_eoa/1),
         {:ok, workspace} <- step(:did, workspace, &ensure_did/1),
         {:ok, workspace} <- step(:chain_registration, workspace, &register_on_chain_step/1),
         {:ok, workspace} <- mark_done(workspace) do
      Log.event(:info, "workspace provisioned",
        event: "workspace.provisioning.completed",
        workspace_id: workspace.id,
        did: workspace.did,
        eoa_address: workspace.eoa_address,
        attempt: attempt
      )

      {:ok, _job} = emit_webhook(workspace)
      :ok
    else
      {:error, step, reason} ->
        # `attempt` and `max_attempts` are what distinguish "will retry" from
        # "gave up", which is the difference between noise and an incident.
        final? = attempt >= max_attempts

        Log.event(:error, "workspace provisioning step failed",
          event: "workspace.provisioning.step_failed",
          workspace_id: workspace.id,
          step: step,
          reason: Log.reason(reason),
          attempt: attempt,
          max_attempts: max_attempts,
          final: final?
        )

        if final? do
          Workspaces.mark_provisioning_failed(workspace.id, format_error(reason))
          {:cancel, reason}
        else
          {:error, reason}
        end

      {:error, reason} ->
        final? = attempt >= max_attempts

        Log.event(:error, "workspace provisioning failed",
          event: "workspace.provisioning.step_failed",
          workspace_id: workspace.id,
          step: :mark_done,
          reason: Log.reason(reason),
          attempt: attempt,
          max_attempts: max_attempts,
          final: final?
        )

        if final? do
          Workspaces.mark_provisioning_failed(workspace.id, format_error(reason))
          {:cancel, reason}
        else
          {:error, reason}
        end
    end
  end

  # Steps are idempotent — each returns early when its field is already set —
  # so a retry logs only the work it actually redoes.
  defp step(name, workspace, fun) do
    already_done? = step_done?(name, workspace)

    case fun.(workspace) do
      {:ok, updated} ->
        unless already_done? do
          Log.event(:info, "workspace provisioning step completed",
            event: "workspace.provisioning.step_completed",
            workspace_id: updated.id,
            step: name
          )
        end

        {:ok, updated}

      {:error, reason} ->
        {:error, name, reason}
    end
  end

  defp step_done?(:signing_key, ws), do: is_binary(ws.signing_key_id)
  defp step_done?(:eoa, ws), do: is_binary(ws.eoa_address)
  defp step_done?(:did, ws), do: is_binary(ws.did)
  defp step_done?(_step, _ws), do: false

  # register_on_chain/1 returns :ok; the step pipeline threads the workspace.
  defp register_on_chain_step(%Workspace{} = ws) do
    with :ok <- register_on_chain(ws), do: {:ok, ws}
  end

  defp ensure_signing_key(%Workspace{signing_key_id: key_id} = ws) when is_binary(key_id),
    do: {:ok, ws}

  defp ensure_signing_key(%Workspace{} = ws) do
    case Key.generate_key("workspace_#{ws.id}_signing") do
      {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} ->
        ws
        |> Workspace.provisioning_progress_changeset(%{
          signing_key_id: key_id,
          signing_public_key_x: x,
          signing_public_key_y: y
        })
        |> Repo.update()

      {:error, _} = error ->
        error
    end
  end

  defp ensure_eoa(%Workspace{eoa_address: addr} = ws) when is_binary(addr), do: {:ok, ws}

  defp ensure_eoa(%Workspace{} = ws) do
    private_key = :crypto.strong_rand_bytes(32)

    case ExSecp256k1.create_public_key(private_key) do
      {:ok, public_key} ->
        <<4, pub_bytes::binary-64>> = public_key
        address_bytes = ExKeccak.hash_256(pub_bytes) |> binary_part(12, 20)
        eoa_address = "0x" <> Base.encode16(address_bytes, case: :lower)
        eoa_key_id = "workspace_#{ws.id}_eoa"

        ws
        |> Workspace.provisioning_progress_changeset(%{
          eoa_address: eoa_address,
          eoa_key_id: eoa_key_id
        })
        |> Repo.update()

      {:error, _} = error ->
        error
    end
  end

  defp ensure_did(%Workspace{did: did} = ws) when is_binary(did), do: {:ok, ws}

  defp ensure_did(%Workspace{eoa_address: eoa_address} = ws) do
    ws
    |> Workspace.provisioning_progress_changeset(%{did: "did:sovra:#{eoa_address}"})
    |> Repo.update()
  end

  defp register_on_chain(%Workspace{} = ws) do
    if Sovra.Ethereum.Client.configured?() do
      case did_registry().register_issuer_did(
             ws.eoa_address,
             ws.signing_public_key_x,
             ws.signing_public_key_y,
             ClaimUtils.base_url()
           ) do
        {:ok, _tx_hash} -> :ok
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :ethereum_not_configured}
    end
  end

  defp mark_done(%Workspace{} = ws) do
    Workspaces.mark_provisioning_done(ws.id, DateTime.utc_now() |> DateTime.truncate(:second))
  end

  defp emit_webhook(%Workspace{} = ws) do
    Webhooks.enqueue(ws.id, "identity.did-generated", %{
      "did" => ws.did,
      "provisioned_at" => DateTime.to_iso8601(ws.provisioned_at)
    })
  end

  defp did_registry,
    do: Application.get_env(:sovra, :did_registry, Sovra.Ethereum.DIDRegistry)

  defp format_error(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp format_error(reason) when is_binary(reason), do: truncate(reason)

  defp format_error(reason) when is_exception(reason),
    do: reason |> Exception.message() |> truncate()

  defp format_error(%Ecto.Changeset{errors: [{field, {msg, _}} | _]}),
    do: truncate("#{field}: #{msg}")

  defp format_error(%Ecto.Changeset{}), do: "validation_error"

  defp format_error(%{"message" => message}) when is_binary(message),
    do: truncate(message)

  defp format_error(reason), do: reason |> inspect() |> truncate()

  defp truncate(string) do
    string
    |> String.replace(~r/\s+/, " ")
    |> String.slice(0, 200)
  end
end
