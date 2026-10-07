defmodule Sovra.Issuer.CredentialTypeRegistrationJob do
  @moduledoc """
  Adds a schema's credential type to the workspace's entry in the on-chain
  issuer registry, then marks every schema of that type `registered`.

  Runs after the schema is created rather than inside the request, because the
  write waits for its receipt and on a public chain that can outlast the
  request. Until it lands the schema is `pending` and nothing is issued from it.

  Keyed by workspace and credential type, not by schema: that is what the
  registry stores, and every revision of a schema shares its type. `isTrusted`
  is read first, so a retry after a write that landed unrecorded converges
  without a second transaction, and a schema reusing a trusted type needs none.

  The last failed attempt marks the schemas `failed`.
  """

  use Oban.Worker, queue: :chain, max_attempts: 5

  use Sovra.Log

  import Ecto.Query

  alias Sovra.Ethereum.ChainError
  alias Sovra.Ethereum.Client
  alias Sovra.Ethereum.IssuerRegistry
  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Repo
  alias Sovra.Workspaces.Workspace

  @doc "The job that registers `schema`'s credential type."
  def new_for(%CredentialSchema{issuer_id: workspace_id, credential_type: credential_type}) do
    new(Log.job_args(%{workspace_id: workspace_id, credential_type: credential_type}))
  end

  @impl Oban.Worker
  def perform(
        %Oban.Job{
          args: %{"workspace_id" => workspace_id, "credential_type" => credential_type},
          attempt: attempt,
          max_attempts: max_attempts
        } = job
      ) do
    Log.adopt_job_context(job)
    Log.put_context(workspace_id: workspace_id)

    case Repo.get(Workspace, workspace_id) do
      nil ->
        {:cancel, :workspace_not_found}

      %Workspace{} = workspace ->
        case register(workspace, credential_type) do
          {:ok, tx_hash} ->
            mark(workspace_id, credential_type, "registered", nil)

            # tx_hash is nil when the type was already trusted and nothing was sent.
            Log.event(:info, "credential type registered on-chain",
              event: "credential.schema.chain_registered",
              workspace_id: workspace_id,
              credential_type: credential_type,
              tx_hash: tx_hash,
              attempt: attempt
            )

            :ok

          {:error, reason} ->
            fail(workspace_id, credential_type, reason, attempt, max_attempts)
        end
    end
  end

  defp register(%Workspace{eoa_address: eoa_address}, credential_type) do
    if Client.configured?() do
      type_id = IssuerRegistry.credential_type_hash(credential_type)

      case issuer_registry().is_trusted(eoa_address, type_id) do
        {:ok, true} -> {:ok, nil}
        {:ok, false} -> issuer_registry().add_credential_types(eoa_address, [type_id])
        {:error, _} = error -> error
      end
    else
      {:error, :ethereum_not_configured}
    end
  end

  # `attempt` and `max_attempts` tell "will retry" from "gave up", and only the
  # final attempt changes what the schema says.
  defp fail(workspace_id, credential_type, reason, attempt, max_attempts) do
    final? = attempt >= max_attempts

    Log.event(:error, "on-chain credential type registration failed",
      event: "credential.schema.chain_registration_failed",
      workspace_id: workspace_id,
      credential_type: credential_type,
      reason: Log.reason(reason),
      attempt: attempt,
      max_attempts: max_attempts,
      final: final?
    )

    if final? do
      mark(workspace_id, credential_type, "failed", ChainError.message(reason))
      {:cancel, reason}
    else
      {:error, reason}
    end
  end

  # Lock, then update in a second statement. A revision holds a lock on its
  # prior version while it inserts a copy of that version's status; waiting for
  # the lock means that revision has committed, and the update's fresh snapshot
  # then includes the row it inserted. A single UPDATE would not see it.
  defp mark(workspace_id, credential_type, status, error) do
    schemas =
      from(s in CredentialSchema,
        where: s.issuer_id == ^workspace_id and s.credential_type == ^credential_type
      )

    Repo.transaction(fn ->
      schemas |> lock("FOR UPDATE") |> select([s], s.id) |> Repo.all()

      Repo.update_all(schemas,
        set: [
          registration_status: status,
          registration_error: error,
          updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
        ]
      )
    end)
  end

  defp issuer_registry,
    do: Application.get_env(:sovra, :issuer_registry, IssuerRegistry)
end
