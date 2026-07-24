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

  alias Sovra.Crypto.Key
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Repo
  alias Sovra.Webhooks
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{
        args: %{"workspace_id" => workspace_id},
        attempt: attempt,
        max_attempts: max_attempts
      }) do
    case Repo.get(Workspace, workspace_id) do
      nil ->
        {:cancel, :workspace_not_found}

      %Workspace{provisioning_status: "done"} ->
        :ok

      %Workspace{} = workspace ->
        run(workspace, attempt, max_attempts)
    end
  end

  defp run(workspace, attempt, max_attempts) do
    with {:ok, workspace} <- ensure_signing_key(workspace),
         {:ok, workspace} <- ensure_eoa(workspace),
         {:ok, workspace} <- ensure_did(workspace),
         :ok <- register_on_chain(workspace),
         {:ok, workspace} <- mark_done(workspace) do
      {:ok, _job} = emit_webhook(workspace)
      :ok
    else
      {:error, reason} ->
        if attempt >= max_attempts do
          Workspaces.mark_provisioning_failed(workspace.id, format_error(reason))
          {:cancel, reason}
        else
          {:error, reason}
        end
    end
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
