defmodule Sovra.Documents.AnchorJob do
  @moduledoc """
  Anchors a signed document: records the issuer's signature over its digest in
  the on-chain signature registry, marks the document `anchored` — or `failed`
  once its retries run out — and announces the outcome with a
  `document.status-changed` webhook.

  Runs after issuance rather than inside the request, because the write waits
  for its receipt and on a public chain that can outlast the request. Until it
  lands the document is `signed`, and a verifier rejects it.

  A retry after a transaction that landed unrecorded, because its receipt poll
  gave up, meets `AlreadyRecorded()`. The original transaction is then found
  through its event, so the document still ends with the real hash.
  """

  use Oban.Worker, queue: :chain, max_attempts: 5

  use Sovra.Log

  alias Sovra.Documents
  alias Sovra.Documents.SignedDocument
  alias Sovra.Ethereum.IssuerRegistry
  alias Sovra.Ethereum.SignatureRegistry
  alias Sovra.Repo
  alias Sovra.Webhooks

  @doc "The job that anchors `document`."
  def new_for(%SignedDocument{id: id}), do: new(Log.job_args(%{document_id: id}))

  @impl Oban.Worker
  def perform(
        %Oban.Job{
          args: %{"document_id" => document_id},
          attempt: attempt,
          max_attempts: max_attempts
        } = job
      ) do
    Log.adopt_job_context(job)

    case SignedDocument |> Repo.get(document_id) |> Repo.preload([:schema, :workspace]) do
      nil ->
        {:cancel, :document_not_found}

      # Settled already, so there is nothing left to anchor.
      %SignedDocument{status: status} when status != "signed" ->
        :ok

      %SignedDocument{} = document ->
        Log.put_context(workspace_id: document.workspace_id)

        case anchor(document) do
          {:ok, tx_hash, anchored_at} ->
            settle(document, %{status: "anchored", tx_hash: tx_hash, anchored_at: anchored_at})

            Log.event(:info, "document anchored",
              event: "document.anchored",
              document_id: document.id,
              workspace_id: document.workspace_id,
              tx_hash: tx_hash,
              digest: Documents.hex(document.digest),
              attempt: attempt
            )

            :ok

          {:error, reason} ->
            fail(document, reason, attempt, max_attempts)
        end
    end
  end

  defp anchor(%SignedDocument{workspace: workspace, schema: schema} = document) do
    type_id = IssuerRegistry.credential_type_hash(schema.credential_type)
    {r, s} = signature_components(document.credential)

    case signature_registry().record(workspace.eoa_address, type_id, document.digest, r, s) do
      {:ok, :already_recorded} ->
        with {:ok, %{tx_hash: tx_hash, recorded_at: recorded_at}} <-
               signature_registry().find_record(workspace.eoa_address, document.digest) do
          {:ok, tx_hash, recorded_at}
        end

      {:ok, tx_hash} ->
        {:ok, tx_hash, DateTime.utc_now() |> DateTime.truncate(:second)}

      {:error, _} = error ->
        error
    end
  end

  # `final` tells "will retry" from "gave up", and only the final attempt
  # changes what the document says. A revert is almost always the signer or the
  # type id not matching the registries; both are a column away from
  # document_id, which keeps this under the attribute ceiling.
  defp fail(document, reason, attempt, max_attempts) do
    final? = attempt >= max_attempts

    Log.event(:error, "document anchoring failed",
      event: "document.anchoring_failed",
      document_id: document.id,
      workspace_id: document.workspace_id,
      digest: Documents.hex(document.digest),
      reason: Log.reason(reason),
      attempt: attempt,
      final: final?
    )

    if final? do
      # A verifier rejects an unanchored document, so a failed one is unusable
      # and has to be reissued.
      settle(document, %{status: "failed"})
      {:cancel, reason}
    else
      {:error, reason}
    end
  end

  # The status and its webhook commit together, so an integrator is told about
  # exactly the state the document is in.
  defp settle(document, attrs) do
    {:ok, updated} =
      Repo.transaction(fn ->
        updated = document |> SignedDocument.status_changeset(attrs) |> Repo.update!()

        {:ok, _jobs} =
          Webhooks.enqueue(updated.workspace_id, "document.status-changed", %{
            "document_id" => updated.id,
            "status" => updated.status,
            "schema_type" => document.schema.credential_type,
            "tx_hash" => updated.tx_hash,
            "anchored_at" => updated.anchored_at && DateTime.to_iso8601(updated.anchored_at),
            "status_at" => DateTime.utc_now() |> DateTime.to_iso8601()
          })

        updated
      end)

    updated
  end

  # The third JWS segment is raw `r ‖ s`, 32 bytes each (RFC 7518), which is
  # what the contract expects. Split on `~` first: the head is the JWT and the
  # tail is the disclosure list, empty for a document.
  defp signature_components(credential) do
    [jwt | _disclosures] = String.split(credential, "~")
    [_header, _payload, signature] = String.split(jwt, ".")
    <<r::binary-32, s::binary-32>> = Base.url_decode64!(signature, padding: false)
    {r, s}
  end

  defp signature_registry,
    do: Application.get_env(:sovra, :signature_registry, SignatureRegistry)
end
