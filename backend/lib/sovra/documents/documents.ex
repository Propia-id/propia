defmodule Sovra.Documents do
  @moduledoc """
  Signed documents: issued and signed directly by an issuer, with no wallet and no
  holder.

  The signed artefact is stored here because there is no holder to keep it. If we
  do not store it, it exists nowhere.
  """

  use Sovra.Log

  alias Sovra.Documents.AnchorJob
  alias Sovra.Documents.Attestation
  alias Sovra.Documents.DocumentLayout
  alias Sovra.Documents.SignedDocument
  alias Sovra.Ethereum.SignatureRegistry
  alias Sovra.Issuer
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Repo
  alias Sovra.Workspaces

  import Ecto.Query

  @doc """
  Signs and stores a document for `schema_id` with `claims`, and queues the
  anchoring of its signature.

  Refuses to sign at all without a signature registry: an unanchorable document
  looks issued while missing the timestamp that makes it worth anything. Returns
  it `signed`; `Sovra.Documents.AnchorJob` moves it to `anchored`, or `failed`
  when the transaction does not go through.
  """
  def issue(workspace_id, schema_id, claims, opts \\ []) when is_map(claims) do
    with {:ok, workspace} <- Workspaces.get_workspace(workspace_id),
         :ok <- Workspaces.assert_provisioned(workspace),
         :ok <- assert_anchoring_configured(),
         {:ok, schema} <- Issuer.get_schema(workspace_id, schema_id),
         :ok <- CredentialSchema.assert_kind(schema, "document"),
         # The anchor reverts until the type is trusted on-chain, and an
         # unanchored document is unusable, so do not sign one.
         :ok <- CredentialSchema.assert_registered(schema),
         :ok <- ClaimUtils.validate_required_claims(schema, claims),
         {:ok, visibility} <- cast_visibility(Keyword.get(opts, :visibility)),
         {:ok, valid_until} <- cast_valid_until(Keyword.get(opts, :valid_until)),
         # Generated before signing so the document's id is covered by the
         # signature, as the payload's `jti`.
         id = Ecto.UUID.generate(),
         {:ok, signed} <-
           Attestation.build(workspace, schema, claims, id, valid_until: valid_until) do
      attrs = %{
        id: id,
        workspace_id: workspace_id,
        schema_id: schema.id,
        credential: signed.credential,
        digest: signed.digest,
        status: "signed",
        visibility: visibility,
        signed_at: DateTime.utc_now() |> DateTime.truncate(:second)
      }

      case insert_document(attrs) do
        {:ok, document} ->
          # Never log the credential itself: it carries the claim values, and
          # anyone holding it can present the document.
          Log.event(:info, "document signed",
            event: "document.signed",
            document_id: document.id,
            workspace_id: workspace.id,
            schema_id: schema.id,
            digest: hex(document.digest),
            visibility: document.visibility
          )

          {:ok, Repo.preload(document, [:schema, :workspace])}

        {:error, changeset} ->
          # Field NAMES only. `inspect(changeset.errors)` used to be here, and
          # an Ecto error tuple can carry the submitted value with it.
          Log.event(:warning, "document insert failed",
            event: "document.rejected",
            workspace_id: workspace.id,
            schema_id: schema.id,
            reason: Log.reason(changeset)
          )

          {:error, changeset}
      end
    end
  end

  # The anchor job is inserted with the document, so a document never exists
  # without the job that will anchor it. The row is stored before anchoring on
  # purpose: a receipt that never arrived is not the same as a transaction that
  # never happened, and dropping the row would risk a signature anchored on a
  # chain that cannot be undone for a document missing from the database.
  defp insert_document(attrs) do
    Ecto.Multi.new()
    |> Ecto.Multi.insert(:document, SignedDocument.create_changeset(attrs))
    |> Oban.insert(:anchor_job, fn %{document: document} -> AnchorJob.new_for(document) end)
    |> Repo.transaction()
    |> case do
      {:ok, %{document: document}} -> {:ok, document}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  defp assert_anchoring_configured do
    if signature_registry().configured?(), do: :ok, else: {:error, :chain_not_configured}
  end

  # `private` also requires a session to read, so nobody sees the document as the
  # issuer laid it out without an account. The default, so publishing is a choice
  # rather than an oversight; `public` is the capability model the id implies.
  defp cast_visibility(nil), do: {:ok, "private"}

  defp cast_visibility(value) when is_binary(value) do
    if value in SignedDocument.visibilities(),
      do: {:ok, value},
      else: {:error, {:invalid_visibility, value}}
  end

  defp cast_visibility(value), do: {:error, {:invalid_visibility, value}}

  # nil is "not supplied", so the schema's validity period applies. The
  # controller has already rejected an explicit null, which it can tell apart
  # from an absent key and this cannot.
  defp cast_valid_until(nil), do: {:ok, nil}

  defp cast_valid_until(%DateTime{} = valid_until),
    do: {:ok, DateTime.truncate(valid_until, :second)}

  defp cast_valid_until(value) do
    case ClaimUtils.parse_valid_until(value) do
      {:ok, valid_until} -> {:ok, valid_until}
      {:error, reason} -> {:error, {:invalid_valid_until, reason}}
    end
  end

  defp signature_registry,
    do: Application.get_env(:sovra, :signature_registry, SignatureRegistry)

  def list(workspace_id) do
    from(d in SignedDocument,
      where: d.workspace_id == ^workspace_id,
      order_by: [desc: :signed_at],
      preload: [:schema, :workspace]
    )
    |> Repo.all()
  end

  def get(workspace_id, id) do
    case Repo.one(
           from d in SignedDocument,
             where: d.id == ^id and d.workspace_id == ^workspace_id,
             preload: [:schema, :workspace]
         ) do
      nil -> {:error, :document_not_found}
      document -> {:ok, document}
    end
  end

  @doc """
  Changes who may read a document.

  Going private closes the link, not the copies: a credential already handed out
  stays readable and verifiable by whoever holds it. Not covered by the
  signature, so this invalidates nothing.
  """
  # Unlike issuance, there is no default here: an explicit change with nothing to
  # change to is a bad request, not a reset.
  def set_visibility(_workspace_id, _id, nil), do: {:error, {:invalid_visibility, nil}}

  def set_visibility(workspace_id, id, visibility) do
    with {:ok, uuid} <- cast_uuid(id),
         {:ok, visibility} <- cast_visibility(visibility),
         {:ok, document} <- get(workspace_id, uuid) do
      document
      |> SignedDocument.visibility_changeset(visibility)
      |> Repo.update()
      |> tap(fn
        {:ok, updated} ->
          # `public` means holding the id is the whole authorization, so this
          # is the moment a document becomes readable by anyone with the link.
          Log.event(:info, "document visibility changed",
            event: "document.visibility.changed",
            document_id: updated.id,
            workspace_id: workspace_id,
            previous_visibility: document.visibility,
            visibility: updated.visibility
          )

        {:error, _} ->
          :ok
      end)
    end
  end

  defp cast_uuid(id) do
    case Ecto.UUID.cast(id) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, :document_not_found}
    end
  end

  @doc """
  Lookup by id with no workspace scope, for the public verification link. Holding
  the id is the authorization.
  """
  def get_public(id) do
    case Repo.one(
           from d in SignedDocument,
             where: d.id == ^id,
             preload: [:schema, :workspace]
         ) do
      nil -> {:error, :document_not_found}
      document -> {:ok, document}
    end
  end

  def hex(binary) when is_binary(binary), do: Base.encode16(binary, case: :lower)

  # ── Layouts ─────────────────────────────────────────────────────────
  #
  # Layouts hang off document schemas, which are the issuer's. `Sovra.Issuer`
  # calls `copy_layout/2` when it revises one.

  # A layout can embed a logo and a page template as data URIs, so the row needs
  # a ceiling. Generous enough for a downscaled A4 template.
  @max_layout_bytes 3_000_000

  @doc """
  Saves the page layout of the latest version of a document schema.

  A layout is presentation, so this creates no schema revision and does not touch
  what gets signed.
  """
  def update_layout(workspace_id, schema_id, layout) do
    with {:ok, schema} <- Issuer.get_schema(workspace_id, schema_id),
         :ok <- CredentialSchema.assert_kind(schema, "document"),
         :ok <- assert_layout_size(layout) do
      case Repo.get_by(DocumentLayout, credential_schema_id: schema.id) do
        nil -> DocumentLayout.create_changeset(schema.id, layout) |> Repo.insert()
        record -> DocumentLayout.update_changeset(record, layout) |> Repo.update()
      end
    end
  end

  @doc """
  The layout of one schema, or nil.
  """
  def layout_for(schema_id) do
    case Repo.get_by(DocumentLayout, credential_schema_id: schema_id) do
      nil -> nil
      record -> record.layout
    end
  end

  @doc """
  Layouts for many schemas at once, as a map keyed by schema id. One query, so
  listing schemas does not turn into one lookup per row.
  """
  def layouts_for(schema_ids) when is_list(schema_ids) do
    from(l in DocumentLayout,
      where: l.credential_schema_id in ^schema_ids,
      select: {l.credential_schema_id, l.layout}
    )
    |> Repo.all()
    |> Map.new()
  end

  @doc """
  Copies a layout onto another schema row. Used when a schema is revised, so the
  new version keeps the page the previous one had.
  """
  def copy_layout(from_schema_id, to_schema_id) do
    case layout_for(from_schema_id) do
      nil -> {:ok, :nothing_to_copy}
      layout -> DocumentLayout.create_changeset(to_schema_id, layout) |> Repo.insert()
    end
  end

  defp assert_layout_size(layout) do
    case Jason.encode(layout) do
      {:ok, json} when byte_size(json) <= @max_layout_bytes -> :ok
      {:ok, _json} -> {:error, :layout_too_large}
      {:error, _reason} -> {:error, :invalid_layout}
    end
  end
end
