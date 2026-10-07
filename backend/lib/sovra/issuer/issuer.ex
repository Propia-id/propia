defmodule Sovra.Issuer do
  @moduledoc """
  Credential issuance domain — credential schemas, offers, and delivery.

  Workspace lifecycle (creation, lookup, listing) lives in `Sovra.Workspaces`.
  This module only deals with the act of issuing credentials from a workspace.
  """

  use Sovra.Log

  alias Sovra.Issuer.{
    CredentialBuilder,
    CredentialSchema,
    CredentialDesign,
    CredentialOffer,
    IssuedCredential,
    MdocElement,
    StatusList,
    TokenHash,
    ClaimUtils,
    ClaimValue,
    SDJWT
  }

  alias Sovra.Crypto.HmacKeyStore
  alias Sovra.Documents
  alias Sovra.Crypto.P256
  alias Sovra.Crypto.WebAuthn
  alias Sovra.Ethereum.{IssuerRegistry, RevocationRegistry}
  alias Sovra.Repo
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  import Ecto.Query

  @c_nonce_expires_in 86400

  # ── Schema Management ──────────────────────────────────

  def create_schema(workspace_id, attrs) do
    attrs = Map.put(attrs, :issuer_id, workspace_id)

    with {:ok, workspace} <- Workspaces.get_workspace(workspace_id),
         :ok <- Workspaces.assert_provisioned(workspace),
         :ok <- assert_doc_type_allowed(attrs, workspace),
         {:ok, schema} <- CredentialSchema.create_changeset(attrs) |> Repo.insert() do
      # No schema_version: create_schema/2 always produces version 1 — the
      # controller never passes one and revisions go through
      # credential.schema.revised, which does carry both versions.
      Log.event(:info, "credential schema created",
        event: "credential.schema.created",
        workspace_id: workspace_id,
        schema_id: schema.id,
        schema_ref: schema.schema_id,
        credential_type: schema.credential_type,
        kind: schema.kind,
        claim_count: length(schema.claims || [])
      )

      case register_credential_type_on_chain(workspace.eoa_address, schema.credential_type) do
        :ok ->
          :ok

        {:error, reason} ->
          # Non-fatal: the schema exists and can issue, but the credential type
          # is not on the registry, so third-party verifiers cannot resolve it.
          Log.event(:error, "on-chain credential type registration failed",
            event: "credential.schema.chain_registration_failed",
            workspace_id: workspace_id,
            schema_id: schema.id,
            credential_type: schema.credential_type,
            eoa_address: workspace.eoa_address,
            reason: Log.reason(reason)
          )
      end

      {:ok, schema}
    else
      {:error, reason} -> reject_schema(:create, workspace_id, nil, reason)
    end
  end

  defp reject_schema(stage, workspace_id, schema_ref, reason) do
    Log.event(:warning, "credential schema operation rejected",
      event: "credential.schema.rejected",
      stage: stage,
      workspace_id: workspace_id,
      schema_ref: schema_ref,
      reason: Log.reason(reason)
    )

    {:error, reason}
  end

  def get_schema(workspace_id, schema_id) do
    query =
      from(s in CredentialSchema,
        where: s.issuer_id == ^workspace_id and s.schema_id == ^schema_id,
        order_by: [desc: :version],
        limit: 1
      )

    case Repo.one(query) do
      nil -> {:error, :schema_not_found}
      schema -> {:ok, schema}
    end
  end

  def get_schema_by_id(id) do
    case Repo.get(CredentialSchema, id) do
      nil -> {:error, :schema_not_found}
      schema -> {:ok, schema}
    end
  end

  def list_schemas(workspace_id) do
    from(s in CredentialSchema,
      where: s.issuer_id == ^workspace_id,
      order_by: [asc: :inserted_at, asc: :version]
    )
    |> Repo.all()
  end

  @doc """
  Schemas of a single kind.
  """
  def list_schemas(workspace_id, kind) when is_binary(kind) do
    from(s in CredentialSchema,
      where: s.issuer_id == ^workspace_id and s.kind == ^kind,
      order_by: [asc: :inserted_at, asc: :version]
    )
    |> Repo.all()
  end

  # Optimistic concurrency: caller must pass `base_version`, the version they
  # observed when they started editing. The transaction locks the latest row
  # FOR UPDATE, verifies it still matches base_version, and only then inserts.
  # The `Postgrex.Error` rescue covers the narrow READ COMMITTED race where two
  # concurrent revisers both pass the check before either commits — the unique
  # constraint on (issuer_id, schema_id, version) catches the loser.
  def revise_schema(workspace_id, schema_id, base_version, attrs)
      when is_integer(base_version) do
    with {:ok, _workspace} <- Workspaces.get_active_workspace(workspace_id) do
      Repo.transaction(fn ->
        prior =
          Repo.one(
            from s in CredentialSchema,
              where: s.issuer_id == ^workspace_id and s.schema_id == ^schema_id,
              order_by: [desc: :version],
              limit: 1,
              lock: "FOR UPDATE"
          )

        case prior do
          nil ->
            Repo.rollback(:schema_not_found)

          %CredentialSchema{version: ^base_version} = prior ->
            do_insert_revision(workspace_id, prior, attrs)

          %CredentialSchema{} ->
            Repo.rollback(:schema_revision_conflict)
        end
      end)
      |> case do
        {:ok, new_schema} ->
          # base_version and the new version together are the whole story of a
          # revision, including the optimistic-concurrency conflicts below.
          Log.event(:info, "credential schema revised",
            event: "credential.schema.revised",
            workspace_id: workspace_id,
            schema_id: new_schema.id,
            schema_ref: schema_id,
            base_version: base_version,
            schema_version: new_schema.version
          )

          {:ok, new_schema}

        {:error, reason} ->
          reject_schema(:revise, workspace_id, schema_id, reason)
      end
    else
      {:error, reason} -> reject_schema(:revise, workspace_id, schema_id, reason)
    end
  end

  defp do_insert_revision(workspace_id, prior, attrs) do
    new_attrs =
      attrs
      |> Map.new(fn {k, v} -> {to_string(k), v} end)
      |> Map.merge(%{
        "issuer_id" => workspace_id,
        "schema_id" => prior.schema_id,
        "credential_type" => prior.credential_type,
        # kind is immutable across revisions: a document schema stays a document
        # schema, otherwise a revision could silently change how it is issued.
        "kind" => prior.kind,
        # format likewise, and more sharply: the docType derives from the schema
        # and is signed into every credential already in a holder's wallet, so a
        # revision that changed it would orphan them.
        "format" => prior.format,
        # And the docType and namespace themselves, for that same reason now
        # that they can be named rather than only derived. Pinning them also
        # closes a bypass: a revision that introduced an ISO docType would
        # otherwise never meet the document-signer check `create_schema/2`
        # applies, because a revision is not a creation.
        "doc_type" => prior.doc_type,
        "namespace" => prior.namespace,
        "version" => prior.version + 1
      })

    try do
      case CredentialSchema.create_changeset(new_attrs) |> Repo.insert() do
        {:ok, new_schema} ->
          inherit_design(prior, new_schema)
          inherit_layout(prior, new_schema)
          new_schema

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    rescue
      e in Postgrex.Error ->
        if Map.get(e.postgres || %{}, :code) == :unique_violation do
          Repo.rollback(:schema_revision_conflict)
        else
          reraise e, __STACKTRACE__
        end
    end
  end

  # Carry the prior version's design to the new schema row so the credential keeps
  # the same look across revisions; admin can still edit it after.
  defp inherit_design(%CredentialSchema{} = prior, %CredentialSchema{} = new_schema) do
    case Repo.get_by(CredentialDesign, credential_schema_id: prior.id) do
      nil ->
        :ok

      design ->
        new_design = %CredentialDesign{
          name: design.name,
          description: design.description,
          display: design.display,
          styles: design.styles,
          back: design.back,
          credential_schema_id: new_schema.id
        }

        case Repo.insert(new_design) do
          {:ok, _} ->
            :ok

          {:error, changeset} ->
            Repo.rollback(changeset)
        end
    end
  end

  # Carry the prior version's page layout to the new schema row so a revised
  # document still renders the same; admin can still edit it after.
  defp inherit_layout(%CredentialSchema{} = prior, %CredentialSchema{} = new_schema) do
    case Documents.copy_layout(prior.id, new_schema.id) do
      {:ok, _} -> :ok
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  # Deleting a schema removes every version sharing the same schema_id within
  # the workspace, atomically. If *any* version has issued credentials or open
  # offers, none are deleted — admins must clean up usage first.
  #
  # Concurrency: locks the schema rows FOR UPDATE inside the transaction. Postgres
  # FK enforcement takes FOR KEY SHARE on the parent row when inserting a child,
  # so concurrent offer/credential inserts that target these schemas block until
  # this transaction commits or rolls back. The rescue clause is a backstop for
  # any FK violation that still surfaces (custom triggers, future tables).
  def delete_schema(workspace_id, id) do
    with {:ok, _workspace} <- Workspaces.get_active_workspace(workspace_id) do
      case do_delete_schema(workspace_id, id) do
        {:ok, %{schema_id: schema_ref, deleted_versions: count} = result} ->
          Log.event(:info, "credential schema deleted",
            event: "credential.schema.deleted",
            workspace_id: workspace_id,
            schema_ref: schema_ref,
            deleted_versions: count
          )

          {:ok, result}

        {:error, reason} ->
          # :schema_in_use is the deletion guard — offers or issued credentials
          # still reference a version. From the UI it looks like a plain
          # failure, so the reason is what makes it explicable.
          reject_schema(:delete, workspace_id, nil, reason)
      end
    else
      {:error, reason} -> reject_schema(:delete, workspace_id, nil, reason)
    end
  end

  defp do_delete_schema(workspace_id, id) do
    Repo.transaction(fn ->
      target =
        Repo.one(
          from s in CredentialSchema,
            where: s.id == ^id and s.issuer_id == ^workspace_id,
            lock: "FOR UPDATE"
        )

      case target do
        nil ->
          Repo.rollback(:schema_not_found)

        %CredentialSchema{schema_id: schema_id_str} ->
          version_ids =
            Repo.all(
              from s in CredentialSchema,
                where: s.issuer_id == ^workspace_id and s.schema_id == ^schema_id_str,
                lock: "FOR UPDATE",
                select: s.id
            )

          if any_version_in_use?(version_ids) do
            Repo.rollback(:schema_in_use)
          else
            try do
              {count, _} =
                Repo.delete_all(from s in CredentialSchema, where: s.id in ^version_ids)

              %{schema_id: schema_id_str, deleted_versions: count}
            rescue
              e in Postgrex.Error ->
                if Map.get(e.postgres || %{}, :code) == :foreign_key_violation do
                  Repo.rollback(:schema_in_use)
                else
                  reraise e, __STACKTRACE__
                end
            end
          end
      end
    end)
  end

  defp any_version_in_use?([]), do: false

  # Mirrors the FK :restrict on offers/credentials: any referencing row blocks
  # deletion. We intentionally don't filter offers by status — `"issued"` offers
  # always have a matching IssuedCredential row, so they'd be caught either way;
  # all other statuses point at live or audit-relevant state we shouldn't orphan.
  defp any_version_in_use?(ids) do
    issued_exists? =
      Repo.exists?(from c in IssuedCredential, where: c.schema_id in ^ids)

    offer_exists? =
      Repo.exists?(from o in CredentialOffer, where: o.schema_id in ^ids)

    issued_exists? or offer_exists?
  end

  # ── Credential Design Management ───────────────────────

  def upsert_design(issuer_id, schema_id, attrs) do
    with {:ok, schema} <- get_schema(issuer_id, schema_id) do
      key =
        if Enum.any?(attrs, fn {k, _} -> is_binary(k) end),
          do: "credential_schema_id",
          else: :credential_schema_id

      attrs = Map.put(attrs, key, schema.id)

      result =
        case Repo.get_by(CredentialDesign, credential_schema_id: schema.id) do
          nil ->
            attrs
            |> CredentialDesign.create_changeset(schema_claims: schema.claims)
            |> Repo.insert()

          design ->
            design
            |> CredentialDesign.update_changeset(attrs, schema_claims: schema.claims)
            |> Repo.update()
        end

      with {:ok, design} <- result do
        Log.event(:info, "credential design updated",
          event: "credential.design.updated",
          workspace_id: issuer_id,
          schema_id: schema.id,
          schema_ref: schema_id,
          design_id: design.id
        )

        {:ok, design}
      end
    end
  end

  def get_design(issuer_id, schema_id) do
    with {:ok, schema} <- get_schema(issuer_id, schema_id) do
      case Repo.get_by(CredentialDesign, credential_schema_id: schema.id) do
        nil -> {:error, :design_not_found}
        design -> {:ok, %{design | credential_schema: schema}}
      end
    end
  end

  def delete_design(issuer_id, schema_id) do
    with {:ok, schema} <- get_schema(issuer_id, schema_id) do
      case Repo.get_by(CredentialDesign, credential_schema_id: schema.id) do
        nil ->
          {:error, :design_not_found}

        design ->
          Repo.delete(design)
          |> tap(fn
            {:ok, _} ->
              Log.event(:info, "credential design deleted",
                event: "credential.design.deleted",
                workspace_id: issuer_id,
                schema_id: schema.id,
                schema_ref: schema_id,
                design_id: design.id
              )

            {:error, _} ->
              :ok
          end)
      end
    end
  end

  def list_designs(issuer_id) do
    from(d in CredentialDesign,
      join: s in CredentialSchema,
      on: s.id == d.credential_schema_id,
      where: s.issuer_id == ^issuer_id,
      order_by: [asc: d.inserted_at],
      preload: [credential_schema: s]
    )
    |> Repo.all()
  end

  # ── Offer & Credential Queries ──────────────────────────

  def list_offers(workspace_id) do
    from(o in CredentialOffer,
      where: o.issuer_id == ^workspace_id,
      order_by: [desc: :inserted_at],
      preload: [:schema]
    )
    |> Repo.all()
  end

  def list_issued_credentials(workspace_id) do
    from(c in IssuedCredential,
      where: c.issuer_id == ^workspace_id,
      order_by: [desc: :issued_at],
      preload: [:schema]
    )
    |> Repo.all()
  end

  # `create_schema/2` has attrs, not a schema, so the same rule
  # `CredentialSchema.assert_can_issue/2` enforces at issuance is applied to the
  # attrs here. Refusing at creation is what keeps the failure attached to the
  # operator who chose the docType, rather than to the citizen whose issuance
  # fails months later.
  defp assert_doc_type_allowed(attrs, workspace) do
    CredentialSchema.assert_can_issue(
      %CredentialSchema{doc_type: Map.get(attrs, :doc_type)},
      workspace
    )
  end

  # ── Credential Offer ───────────────────────────────────

  @doc """
  Creates a credential offer.

  `:valid_until` overrides the schema's `validity_period` with an absolute
  instant. It is stored on the offer rather than applied now because the
  credential is not built until the holder redeems the offer, possibly days
  later — the whole reason a relative period cannot express "expire exactly
  when the credential I am replacing did".
  """
  def create_credential_offer(workspace_id, schema_id, claims, opts \\ []) do
    with {:ok, workspace} <- Workspaces.get_workspace(workspace_id),
         :ok <- Workspaces.assert_provisioned(workspace),
         {:ok, schema} <- get_schema(workspace_id, schema_id),
         :ok <- assert_kind(schema, "credential"),
         # An ISO docType is trusted through the workspace's certificate chain,
         # so issuing under one without a registered document signer produces a
         # credential that resolves to nobody. Checked again here rather than
         # only at schema creation: the schema outlives the check, and a
         # workspace can hold one whose signer was never registered.
         :ok <- CredentialSchema.assert_can_issue(schema, workspace),
         :ok <- validate_claims(schema, claims),
         # After the workspace and schema checks, so a caller reaching for a
         # workspace that is not theirs is answered on that, not handed input
         # feedback about a resource they were never entitled to.
         {:ok, valid_until} <- cast_valid_until(Keyword.get(opts, :valid_until)),
         # Both of these fail here rather than at delivery, and before the offer
         # row exists: a bad value would otherwise surface as a 500 in the middle
         # of the holder's wallet flow, long after the operator who supplied it
         # has gone — and a rejected attachment would sit in `claims` until the
         # offer expired. Each is a no-op for the format it does not govern.
         :ok <- ClaimValue.validate(schema, claims),
         :ok <- MdocElement.encodable?(schema, claims) do
      {plaintext_code, code_hash} = TokenHash.generate_and_hash(32)
      offer_id = Ecto.UUID.generate()

      expires_at =
        DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)

      attrs_base = %{
        id: offer_id,
        issuer_id: workspace_id,
        schema_id: schema.id,
        pre_authorized_code_hash: code_hash,
        claims: claims,
        status_purpose: "revocation",
        expires_at: expires_at,
        credential_valid_until: valid_until
      }

      case insert_offer_with_retry(workspace, attrs_base) do
        {:ok, offer} ->
          # claim COUNT, never the claims: they are government-issued PII
          # (names, document numbers, dates of birth) and New Relic would
          # flatten a claims map straight into queryable attributes.
          # offer.id is the credential_id for the whole flow that follows.
          #
          # Trimmed to fit the agent's 10-attribute ceiling (see Sovra.Log):
          # credential_type, tx_code_required and expires_at are all columns
          # one join from credential_id, and status_purpose is hardcoded
          # "revocation" at this call site. claim_count stays because deriving
          # it means reading the claims column itself.
          Log.event(:info, "credential offer created",
            event: "credential.offer.created",
            credential_id: offer.id,
            workspace_id: workspace_id,
            schema_id: schema.id,
            schema_ref: schema.schema_id,
            status_list_index: offer.status_list_index,
            claim_count: map_size(claims)
          )

          offer_uri = build_offer_uri(plaintext_code, offer, schema, workspace)

          credential_preview =
            CredentialBuilder.preview(workspace, schema, claims,
              status_list_index: offer.status_list_index,
              valid_until: valid_until
            )

          {:ok,
           %{
             offer: offer,
             offer_uri: offer_uri,
             pre_authorized_code: plaintext_code,
             credential: credential_preview
           }}

        {:error, reason} ->
          Log.event(:warning, "credential offer creation failed",
            event: "credential.request.rejected",
            stage: :offer,
            workspace_id: workspace_id,
            schema_id: schema.id,
            reason: Log.reason(reason)
          )

          {:error, reason}
      end
    else
      {:error, reason} ->
        Log.event(:warning, "credential offer creation rejected",
          event: "credential.request.rejected",
          stage: :offer,
          workspace_id: workspace_id,
          reason: Log.reason(reason)
        )

        {:error, reason}
    end
  end

  @max_allocation_attempts 3
  @max_widens_per_call 16

  defp insert_offer_with_retry(workspace, attrs) do
    status_list = fetch_status_list!(workspace.id, attrs.status_purpose)
    do_insert_with_retry(workspace, attrs, status_list.width, 0, 0)
  end

  defp do_insert_with_retry(workspace, attrs, width, _attempt, widens)
       when widens > @max_widens_per_call do
    exhausted(workspace, attrs, width, :widen_limit_reached, widens)
  end

  defp do_insert_with_retry(workspace, attrs, width, attempt, widens)
       when attempt >= @max_allocation_attempts do
    case widen_status_list(workspace.id, attrs.status_purpose, width) do
      {:ok, new_width} ->
        # Rare and worth seeing: the status list doubles, which changes the
        # bitmap every third-party verifier fetches.
        Log.event(:info, "status list widened",
          event: "issuance.status_index.widened",
          workspace_id: workspace.id,
          status_purpose: attrs.status_purpose,
          previous_width: width,
          width: new_width,
          widens_this_call: widens + 1
        )

        do_insert_with_retry(workspace, attrs, new_width, 0, widens + 1)

      {:error, :bitmap_exhausted} ->
        exhausted(workspace, attrs, width, :max_width_reached, widens)
    end
  end

  defp do_insert_with_retry(workspace, attrs, width, attempt, widens) do
    with {:ok, index} <-
           assign_status_list_index(workspace, attrs.id, attrs.status_purpose, attempt, width) do
      changeset = CredentialOffer.create_changeset(Map.put(attrs, :status_list_index, index))

      case Repo.insert(changeset) do
        {:ok, offer} ->
          {:ok, offer}

        {:error, %Ecto.Changeset{errors: errors} = changeset} ->
          if status_index_collision?(errors) do
            do_insert_with_retry(workspace, attrs, width, attempt + 1, widens)
          else
            {:error, changeset}
          end
      end
    end
  end

  # Nothing else reports this: offer creation simply starts failing for the
  # workspace, and no new credential of that purpose can be issued until the
  # cause is understood.
  defp exhausted(workspace, attrs, width, reason, widens) do
    # The two bounds are compile-time constants (3 and 16) and live in the
    # issuance_status_index_exhausted alert description rather than on every
    # record.
    Log.event(:error, "status list index allocation exhausted",
      event: "issuance.status_index.exhausted",
      workspace_id: workspace.id,
      status_purpose: attrs.status_purpose,
      width: width,
      reason: reason,
      widens_this_call: widens
    )

    {:error, :bitmap_exhausted}
  end

  defp fetch_status_list!(workspace_id, purpose) do
    case Repo.get_by(StatusList, workspace_id: workspace_id, status_purpose: purpose) do
      nil ->
        raise "missing status_lists row for workspace=#{workspace_id} purpose=#{purpose} — invariant violation"

      %StatusList{} = sl ->
        sl
    end
  end

  @doc false
  # Public for testing — internal callers should go through `do_insert_with_retry/5`.
  def widen_status_list(workspace_id, purpose, observed_width) do
    Repo.transaction(fn ->
      query =
        from sl in StatusList,
          where: sl.workspace_id == ^workspace_id and sl.status_purpose == ^purpose,
          lock: "FOR UPDATE"

      sl = Repo.one!(query)

      cond do
        sl.width > observed_width ->
          sl.width

        sl.width >= StatusList.max_width() ->
          Repo.rollback(:bitmap_exhausted)

        true ->
          sl
          |> StatusList.bump_width_changeset()
          |> Repo.update!()
          |> Map.fetch!(:width)
      end
    end)
  end

  defp status_index_collision?(errors) do
    expected = CredentialOffer.status_index_constraint() |> to_string()

    Enum.any?(errors, fn
      {:status_list_index, {_, [constraint: :unique, constraint_name: ^expected]}} -> true
      _ -> false
    end)
  end

  @doc """
  Re-mint the pre-authorized code of an unclaimed offer and rebuild its QR.

  The offer URI carries the plaintext code, and only its SHA-256 is persisted,
  so an operator who closes the QR cannot get it back: the offer stays valid
  and claimable but unreachable until it expires. Rather than storing the
  plaintext — a live bearer token at rest, which is what the hashing avoids —
  this rotates the code and rebuilds the URI around it.

  The offer keeps its `id` and `status_list_index`, so the credential the
  holder ends up with is the one the operator already created.

  Only a `pending`, unexpired offer can be regenerated. At `token_exchanged`
  the wallet is mid-flow and already holds an access token; at `issued` the
  code hash and claims are gone.
  """
  def regenerate_offer_code(workspace_id, offer_id) do
    with {:ok, workspace} <- Workspaces.get_workspace(workspace_id),
         :ok <- Workspaces.assert_provisioned(workspace),
         {:ok, offer} <- get_pending_offer(workspace_id, offer_id) do
      {plaintext_code, code_hash} = TokenHash.generate_and_hash(32)

      case Repo.update(CredentialOffer.regenerated_code_changeset(offer, code_hash)) do
        {:ok, offer} ->
          # Worth an event of its own: the previous code stops working here, so
          # a wallet failing to redeem a QR an operator shared earlier is
          # explained by this line and nothing else.
          Log.event(:info, "credential offer code regenerated",
            event: "credential.offer.code_regenerated",
            credential_id: offer.id,
            workspace_id: workspace_id,
            schema_id: offer.schema_id
          )

          {:ok,
           %{
             offer: offer,
             offer_uri: build_offer_uri(plaintext_code, offer, offer.schema, workspace),
             pre_authorized_code: plaintext_code
           }}

        {:error, reason} ->
          reject_regeneration(workspace_id, offer_id, reason)
      end
    else
      {:error, reason} -> reject_regeneration(workspace_id, offer_id, reason)
    end
  end

  # Ownership before state: a caller reaching for an offer that is not theirs is
  # answered on that alone, never told whether some other workspace's offer is
  # still claimable.
  defp get_pending_offer(workspace_id, offer_id) do
    case Repo.get_by(CredentialOffer, id: offer_id, issuer_id: workspace_id) do
      nil ->
        {:error, :offer_not_found}

      %{status: "pending"} = offer ->
        if DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt do
          {:error, :offer_expired}
        else
          {:ok, Repo.preload(offer, :schema)}
        end

      offer ->
        {:error, {:offer_not_pending, offer.status}}
    end
  end

  defp reject_regeneration(workspace_id, offer_id, reason) do
    Log.event(:warning, "credential offer code regeneration rejected",
      event: "credential.request.rejected",
      stage: :offer_regenerate,
      credential_id: offer_id,
      workspace_id: workspace_id,
      reason: Log.reason(reason)
    )

    {:error, reason}
  end

  def build_offer_uri(pre_authorized_code, offer, schema, workspace) do
    credential_issuer = "#{ClaimUtils.base_url()}/#{workspace.did}"

    offer_json =
      Jason.encode!(%{
        "credential_issuer" => credential_issuer,
        "credential_configuration_ids" => [schema.credential_type],
        "grants" => %{
          "urn:ietf:params:oauth:grant-type:pre-authorized_code" =>
            Map.merge(
              %{"pre-authorized_code" => pre_authorized_code},
              if(offer.tx_code,
                do: %{"tx_code" => %{"input_mode" => "numeric", "length" => 6}},
                else: %{}
              )
            )
        }
      })

    "openid-credential-offer://?credential_offer=#{URI.encode(offer_json)}"
  end

  # ── Token Exchange ─────────────────────────────────────

  def exchange_token(pre_authorized_code, tx_code \\ nil) do
    code_hash = TokenHash.hash(pre_authorized_code)

    case Repo.get_by(CredentialOffer, pre_authorized_code_hash: code_hash) do
      nil ->
        # No offer, so no credential_id to correlate on — the only signal that
        # a wallet (or a scanner) presented a code we do not know.
        reject_request(:token, nil, nil, :invalid_code)

      %{status: "pending"} = offer ->
        cond do
          DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt ->
            reject_request(:token, offer.id, offer.issuer_id, :offer_expired)

          offer.tx_code != nil and offer.tx_code != tx_code ->
            check_tx_code_lockout(offer)

          true ->
            {plaintext_token, token_hash} = TokenHash.generate_and_hash(32)
            c_nonce = random_hex(16)

            changeset =
              CredentialOffer.token_exchanged_changeset(offer, %{
                access_token_hash: token_hash,
                c_nonce: c_nonce
              })

            case Repo.update(changeset) do
              {:ok, _} ->
                # The wallet's half of the flow was anonymous in the logs until
                # here: only the token hash is presented, so the offer has to be
                # resolved to recover the credential_id that joins this to the
                # offer and to the issuance that follows.
                Log.event(:info, "credential token exchanged",
                  event: "credential.token.exchanged",
                  credential_id: offer.id,
                  workspace_id: offer.issuer_id,
                  schema_id: offer.schema_id
                )

                {:ok,
                 %{
                   access_token: plaintext_token,
                   c_nonce: c_nonce,
                   c_nonce_expires_in: @c_nonce_expires_in,
                   expires_in: 86400
                 }}

              {:error, reason} ->
                reject_request(:token, offer.id, offer.issuer_id, reason)
            end
        end

      other ->
        reject_request(:token, other.id, other.issuer_id, :code_already_used)
    end
  end

  # Every expected 4xx on the wallet rail. Warning, not error: these are the
  # holder's or the client's, and the level is what keeps them out of the
  # issuance-broken alert.
  defp reject_request(stage, credential_id, workspace_id, reason) do
    Log.event(:warning, "credential request rejected",
      event: "credential.request.rejected",
      stage: stage,
      credential_id: credential_id,
      workspace_id: workspace_id,
      reason: Log.reason(reason)
    )

    {:error, reason}
  end

  defp check_tx_code_lockout(offer) do
    bucket = "tx_code:#{offer.id}"

    case Hammer.check_rate(bucket, 300_000, 5) do
      {:allow, _count} ->
        {:error, :invalid_tx_code}

      {:deny, _limit} ->
        # The transaction code is the only thing standing between a leaked
        # offer QR and a credential, so exhausting its attempts is a signal
        # worth keeping. offer.id is the credential_id for the whole flow.
        Log.event(:warning, "offer locked after too many tx_code attempts",
          event: "issuance.tx_code.locked_out",
          credential_id: offer.id,
          workspace_id: offer.issuer_id
        )

        {:error, :offer_locked}
    end
  end

  # ── Credential Delivery ────────────────────────────────

  def issue_credential(access_token, credential_configuration_id, proof) do
    token_hash = TokenHash.hash(access_token)

    case Repo.get_by(CredentialOffer, access_token_hash: token_hash) do
      nil ->
        reject_request(:credential, nil, nil, :invalid_token)

      %{status: "token_exchanged"} = offer ->
        if DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt do
          reject_request(:credential, offer.id, offer.issuer_id, :offer_expired)
        else
          with {:ok, schema} <- get_schema_by_id(offer.schema_id),
               :ok <- ensure_configuration_matches(schema, credential_configuration_id),
               {:ok, %{holder_did: holder_did, holder_key: holder_key}} <-
                 verify_proof(proof, offer.c_nonce) do
            deliver_credential(offer, holder_did, holder_key)
          else
            {:error, reason} ->
              reject_request(:credential, offer.id, offer.issuer_id, reason)
          end
        end

      other ->
        reject_request(:credential, other.id, other.issuer_id, :credential_already_issued)
    end
  end

  defp ensure_configuration_matches(%{credential_type: type}, type) when is_binary(type), do: :ok
  defp ensure_configuration_matches(_, _), do: {:error, :invalid_credential_request}

  defp deliver_credential(offer, holder_did, holder_key) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    # No assert_provisioned here: an offer can only exist if the workspace
    # was provisioned at offer-creation time (gated in create_credential_offer/3),
    # and the cryptographic columns persist across retries. Letting the
    # holder's OID4VCI flow finish keeps us spec-compliant — the credential
    # endpoint must not return non-OID4VCI error codes.
    with {:ok, workspace} <- Workspaces.get_workspace(offer.issuer_id),
         {:ok, schema} <- get_schema_by_id(offer.schema_id),
         {:ok, %{credential: credential, format: format, expires_at: expires_at} = built} <-
           CredentialBuilder.build(workspace, schema, offer.claims, holder_did, holder_key,
             status_list_index: offer.status_list_index,
             now: now,
             valid_until: offer.credential_valid_until
           ) do
      # Reuse offer.id as the IssuedCredential's primary key so external
      # integrators have a single stable `credential_id` from offer creation
      # through webhook delivery and lifecycle changes.
      issued_cred_changeset =
        IssuedCredential.create_changeset(%{
          id: offer.id,
          issuer_id: offer.issuer_id,
          schema_id: offer.schema_id,
          holder_did: holder_did,
          status_list_index: offer.status_list_index,
          status_purpose: "revocation",
          issued_at: now,
          expires_at: expires_at
        })

      # Before the transaction: with an attachment this decodes the largest
      # disclosure the platform produces, and nothing about it needs a
      # connection held open.
      {webhook_credential, attachment} = strip_attachment(credential, schema)

      Repo.transaction(fn ->
        case Repo.insert(issued_cred_changeset) do
          {:ok, cred} ->
            case Repo.update(CredentialOffer.issued_changeset(offer)) do
              {:ok, _} ->
                # Same name as the webhook, so support can pivot between what
                # we told the customer and what we did on one identifier.
                # No expires_at: it is a column on the row this event names.
                Log.event(:info, "credential issued",
                  event: "credential.issued",
                  credential_id: cred.id,
                  workspace_id: cred.issuer_id,
                  schema_id: cred.schema_id,
                  credential_type: schema.credential_type,
                  holder_did: cred.holder_did,
                  status_list_index: cred.status_list_index
                )

                {:ok, _} =
                  Sovra.Webhooks.enqueue(
                    offer.issuer_id,
                    "credential.issued",
                    %{
                      "credential_id" => cred.id,
                      "holder_did" => cred.holder_did,
                      "schema_type" => schema.credential_type,
                      "issued_at" => DateTime.to_iso8601(cred.issued_at),
                      "expires_at" => cred.expires_at && DateTime.to_iso8601(cred.expires_at),
                      "credential" => webhook_credential,
                      "format" => format
                    }
                    |> maybe_put_doc_type(built)
                    |> maybe_put_attachment(attachment)
                  )

                %{credential: credential, format: format}

              {:error, reason} ->
                Repo.rollback(reason)
            end

          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    end
  end

  # An additive field: integrators already branch on `format`, and an sd-jwt
  # payload gains nothing from a null key.
  defp maybe_put_doc_type(payload, %{doc_type: doc_type}) when is_binary(doc_type),
    do: Map.put(payload, "doc_type", doc_type)

  defp maybe_put_doc_type(payload, _built), do: payload

  defp maybe_put_attachment(payload, nil), do: payload
  defp maybe_put_attachment(payload, attachment), do: Map.put(payload, "attachment", attachment)

  # The webhook ships the credential whole, so a schema carrying an attachment
  # would ship half a megabyte of PDF — as a ~750 KB body, retried eight times
  # against a customer endpoint with a five-second timeout. That is a delivery
  # queue we took down ourselves, to hand back a file the consumer uploaded
  # minutes earlier. It gets a description of the attachment instead.
  #
  # The credential delivered to the holder is untouched: this narrows what the
  # webhook carries, nothing else.
  #
  # A schema stored before attachment keys were required may declare one with
  # no key. Such a claim can carry no value, so there is nothing to strip.
  defp strip_attachment(credential, %{format: "vc+sd-jwt"} = schema) do
    case ClaimValue.attachment_claims(schema.claims) do
      [%{"key" => key} | _] when is_binary(key) -> SDJWT.without_claim(credential, key)
      _ -> {credential, nil}
    end
  end

  defp strip_attachment(credential, _schema), do: {credential, nil}

  # ── Proof Verification ─────────────────────────────────

  defp verify_proof(nil, _nonce), do: {:error, :invalid_proof}

  defp verify_proof(proof, nonce) do
    with "jwt" <- Map.get(proof, "proof_type") || Map.get(proof, :proof_type),
         jwt when is_binary(jwt) <- Map.get(proof, "jwt") || Map.get(proof, :jwt),
         [header_b64, payload_b64, sig_b64] <- String.split(jwt, "."),
         {:ok, header_json} <- Base.url_decode64(header_b64, padding: false),
         {:ok, payload_json} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, header} <- Jason.decode(header_json),
         {:ok, payload} <- Jason.decode(payload_json),
         true <- header["typ"] == "openid4vci-proof+jwt",
         true <- payload["nonce"] == nonce,
         holder_did when is_binary(holder_did) <- payload["iss"],
         {:ok, {pub_x, pub_y}} <- extract_jwk_coordinates(header["jwk"]),
         signing_input = header_b64 <> "." <> payload_b64,
         true <- verify_proof_sig(header["alg"], signing_input, sig_b64, {pub_x, pub_y}) do
      # The coordinates travel with the DID because mdoc binds to the key
      # itself (MSO.deviceKeyInfo) rather than to a DID reference the way
      # SD-JWT's `cnf` does. Both proof algorithms carry the same P-256 jwk,
      # which is exactly why the holder's existing passkey can serve as the
      # mdoc device key.
      {:ok, %{holder_did: holder_did, holder_key: {pub_x, pub_y}}}
    else
      _ -> {:error, :invalid_proof}
    end
  end

  # Holder proof-of-possession signature. The key is the self-asserted header
  # `jwk` (OID4VCI binds the credential to it). ES256 is a plain JWS; WebAuthn
  # is an Aligned passkey assertion over sha256(signing_input) — same format the
  # presentation KB-JWT uses (see Sovra.Credentials.SDJWT).
  defp verify_proof_sig("ES256", signing_input, sig_b64, {pub_x, pub_y}) do
    case Base.url_decode64(sig_b64, padding: false) do
      {:ok, <<r::binary-32, s::binary-32>>} ->
        P256.verify(:crypto.hash(:sha256, signing_input), %{r: r, s: s}, {pub_x, pub_y})

      _ ->
        false
    end
  end

  defp verify_proof_sig("WebAuthn", signing_input, sig_b64, {pub_x, pub_y}) do
    with {:ok, sig_bytes} <- Base.url_decode64(sig_b64, padding: false),
         {:ok, assertion} <- WebAuthn.parse_assertion(sig_bytes) do
      WebAuthn.valid?(:crypto.hash(:sha256, signing_input), assertion, {pub_x, pub_y})
    else
      _ -> false
    end
  end

  defp verify_proof_sig(_, _, _, _), do: false

  defp extract_jwk_coordinates(%{"x" => x_b64, "y" => y_b64}) do
    with {:ok, x} <- Base.url_decode64(x_b64, padding: false),
         {:ok, y} <- Base.url_decode64(y_b64, padding: false),
         true <- byte_size(x) == 32 and byte_size(y) == 32 do
      {:ok, {x, y}}
    else
      _ -> :error
    end
  end

  defp extract_jwk_coordinates(_), do: :error

  # ── Validation Helpers ─────────────────────────────────

  # A credential schema is issued to a wallet over OID4VCI; a document schema is
  # signed directly by the issuer. Mixing the two flows is always a mistake, so
  # both entry points assert the kind rather than trusting the caller.
  defp assert_kind(schema, expected), do: CredentialSchema.assert_kind(schema, expected)

  defp validate_claims(schema, claims), do: ClaimUtils.validate_required_claims(schema, claims)

  # Absent is the only way to ask for the schema's default. An explicit null is
  # rejected rather than quietly meaning the same thing: a caller that sends one
  # is describing an expiry it could not compute, and silently issuing the
  # schema default would hand it a date it never chose.
  defp cast_valid_until(nil), do: {:ok, nil}

  defp cast_valid_until(%DateTime{} = valid_until),
    do: {:ok, DateTime.truncate(valid_until, :second)}

  defp cast_valid_until(value) do
    case ClaimUtils.parse_valid_until(value) do
      {:ok, valid_until} -> {:ok, valid_until}
      {:error, reason} -> {:error, {:invalid_valid_until, reason}}
    end
  end

  defp random_hex(bytes) do
    :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)
  end

  # ── Credential Status Management ─────────────────────

  def revoke_credential(workspace_id, credential_id) do
    change_credential_status(
      workspace_id,
      credential_id,
      "revoked",
      "credential.revoked",
      fn addr, idx -> revocation_registry().revoke(addr, idx) end
    )
  end

  def suspend_credential(workspace_id, credential_id) do
    change_credential_status(
      workspace_id,
      credential_id,
      "suspended",
      "credential.suspended",
      fn addr, idx -> revocation_registry().suspend(addr, idx) end
    )
  end

  def unsuspend_credential(workspace_id, credential_id) do
    change_credential_status(
      workspace_id,
      credential_id,
      "issued",
      "credential.unsuspended",
      fn addr, idx -> revocation_registry().unsuspend(addr, idx) end
    )
  end

  defp change_credential_status(workspace_id, credential_id, new_status, event, chain_call) do
    with {:ok, cred} <- resolve_issued_or_pending(workspace_id, credential_id),
         {:ok, workspace} <- Workspaces.get_workspace(workspace_id),
         :ok <- Workspaces.assert_provisioned(workspace),
         :ok <- validate_status_transition(cred, new_status),
         {:ok, tx_hash} <-
           maybe_sync_chain_status(chain_call, workspace_id, cred.status_list_index),
         {:ok, updated} <-
           cred |> IssuedCredential.status_changeset(new_status) |> Repo.update() do
      {:ok, schema} = get_schema_by_id(updated.schema_id)

      # `event` is already the webhook's event name, so the log and the webhook
      # carry the same vocabulary for free. Revocation is the mutation with
      # legal weight and the one most likely to be disputed, and it left no
      # trace outside the database until now — tx_hash is what ties it to the
      # on-chain status list a third-party verifier will read.
      # No `status`: the event name is the outcome. credential.revoked ->
      # "revoked", .suspended -> "suspended", .unsuspended -> "issued", and
      # previous_status is the half the name cannot carry — issued -> revoked
      # and suspended -> revoked are different stories. schema_id and
      # credential_type are on credential.issued under the same credential_id.
      Log.event(:info, "credential status changed",
        event: event,
        credential_id: updated.id,
        workspace_id: workspace_id,
        holder_did: updated.holder_did,
        previous_status: cred.status,
        status_list_index: updated.status_list_index,
        tx_hash: tx_hash
      )

      {:ok, _job} =
        Sovra.Webhooks.enqueue(workspace_id, event, %{
          "credential_id" => updated.id,
          "holder_did" => updated.holder_did,
          "schema_type" => schema.credential_type,
          "status_at" => DateTime.utc_now() |> DateTime.to_iso8601()
        })

      {:ok, updated}
    else
      {:error, reason} ->
        Log.event(:warning, "credential status change rejected",
          event: "credential.status_change.rejected",
          credential_id: credential_id,
          workspace_id: workspace_id,
          status: new_status,
          reason: Log.reason(reason)
        )

        {:error, reason}
    end
  end

  # Used by lifecycle ops: only an *issued* credential can transition. If the
  # id resolves to a pending offer instead, surface that as a distinct error so
  # the controller can return 422 (different from a true 404).
  defp resolve_issued_or_pending(workspace_id, id) do
    case get_credential(workspace_id, id) do
      {:ok, {:issued, cred}} -> {:ok, cred}
      {:ok, {:pending, _offer}} -> {:error, :credential_not_yet_issued}
      {:error, :credential_not_found} = err -> err
    end
  end

  # Returns the transaction hash so the caller can record which on-chain write
  # carried the status change; `{:ok, nil}` when there is no chain configured.
  defp maybe_sync_chain_status(chain_call, workspace_id, index) do
    if ethereum_configured?() do
      case chain_call.(get_workspace_eoa(workspace_id), index) do
        {:ok, tx_hash} -> {:ok, tx_hash}
        {:error, _} = error -> error
      end
    else
      {:ok, nil}
    end
  end

  def get_issued_credential(workspace_id, id) do
    case Repo.get_by(IssuedCredential, id: id, issuer_id: workspace_id) do
      nil ->
        {:error, :credential_not_found}

      cred ->
        {:ok, Repo.preload(cred, :schema)}
    end
  end

  @doc """
  Resolve a credential by id, including offers that haven't been claimed yet.
  After offer creation Sovra Gov already holds the future credential's id
  (offer.id == issued_credentials.id once the holder claims), so the GET
  endpoint must reflect the in-flight state instead of 404'ing.

  Returns `{:ok, {:issued, %IssuedCredential{}}}` once the holder claimed,
  `{:ok, {:pending, %CredentialOffer{}}}` while the offer is outstanding, or
  `{:error, :credential_not_found}` if neither table has a row for this id
  in this workspace.
  """
  def get_credential(workspace_id, id) do
    case get_issued_credential(workspace_id, id) do
      {:ok, cred} ->
        {:ok, {:issued, cred}}

      {:error, :credential_not_found} ->
        case Repo.get_by(CredentialOffer, id: id, issuer_id: workspace_id) do
          nil -> {:error, :credential_not_found}
          offer -> {:ok, {:pending, Repo.preload(offer, :schema)}}
        end
    end
  end

  defp validate_status_transition(%{status: "issued"}, "revoked"), do: :ok
  defp validate_status_transition(%{status: "issued"}, "suspended"), do: :ok
  defp validate_status_transition(%{status: "suspended"}, "revoked"), do: :ok
  defp validate_status_transition(%{status: "suspended"}, "issued"), do: :ok
  defp validate_status_transition(_cred, _target), do: {:error, :invalid_status_transition}

  defp get_workspace_eoa(workspace_id) do
    Repo.get!(Workspace, workspace_id).eoa_address
  end

  # ── Status List Index Assignment ─────────────────────
  #
  # Indices are derived deterministically via HMAC over the workspace's
  # `status_index_secret_key_id`. The truncation `width` comes from the
  # per-(workspace, purpose) `status_lists` row and grows on exhaustion.
  # Uniqueness is enforced by the DB unique index on
  # `(issuer_id, status_list_index, status_purpose)`; on collision the
  # caller bumps `attempt` (and eventually `width`) and re-allocates.

  defp assign_status_list_index(
         %Workspace{status_index_secret_key_id: key_id},
         offer_id,
         purpose,
         attempt,
         width
       )
       when is_binary(key_id) and is_integer(width) do
    payload = "sovra:status-index:#{purpose}:#{offer_id}:#{attempt}"

    case HmacKeyStore.hmac(key_id, payload) do
      {:ok, mac} ->
        <<index::unsigned-big-integer-size(width), _rest::bitstring>> = mac
        {:ok, index}

      {:error, _} = error ->
        error
    end
  end

  # ── On-Chain Registration Helpers ─────────────────────

  defp initialize_bitmaps_on_chain(eoa_address) do
    if ethereum_configured?() do
      with {:ok, _} <- revocation_registry().initialize_bitmap(eoa_address, 0),
           {:ok, _} <- revocation_registry().initialize_bitmap(eoa_address, 1) do
        :ok
      end
    else
      {:error, :ethereum_not_configured}
    end
  end

  defp register_credential_type_on_chain(eoa_address, credential_type) do
    if ethereum_configured?() do
      type_hash = IssuerRegistry.credential_type_hash(credential_type)

      case IssuerRegistry.is_registered(eoa_address) do
        {:ok, true} ->
          case IssuerRegistry.add_credential_types(eoa_address, [type_hash]) do
            {:ok, _tx_hash} -> :ok
            {:error, reason} -> {:error, reason}
          end

        {:ok, false} ->
          with {:ok, _tx_hash} <- IssuerRegistry.register_issuer(eoa_address, [type_hash]),
               :ok <- initialize_bitmaps_on_chain(eoa_address) do
            :ok
          end

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :ethereum_not_configured}
    end
  end

  defp ethereum_configured?, do: Sovra.Ethereum.Client.configured?()

  defp revocation_registry,
    do: Application.get_env(:sovra, :revocation_registry, RevocationRegistry)
end
