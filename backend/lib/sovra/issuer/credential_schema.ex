defmodule Sovra.Issuer.CredentialSchema do
  use Ecto.Schema
  import Ecto.Changeset

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Mdl.Template

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @kinds ~w(credential document)
  @formats ~w(vc+sd-jwt mso_mdoc)

  schema "credential_schemas" do
    field :schema_id, :string
    field :credential_type, :string
    field :name, :string
    field :claims, {:array, :map}
    field :validity_period, :string
    field :version, :integer, default: 1

    # "credential" → issued to a wallet over OID4VCI, bound to a holder key.
    # "document"   → issued and signed directly by the issuer, no holder.
    field :kind, :string, default: "credential"

    # Wire format. "vc+sd-jwt" is JSON/JWT; "mso_mdoc" is ISO 18013-5 CBOR.
    # Immutable across revisions (see `Sovra.Issuer.do_insert_revision/3`): the
    # docType derives from the schema and is signed into every credential
    # already issued, so flipping it would orphan them.
    field :format, :string, default: "vc+sd-jwt"

    # Operator-supplied identifiers, for a workspace issuing under an issuing
    # authority's certificate rather than under a Sovra-generated docType.
    # Null on every schema that generates its own, which is all of them today.
    #
    # Naming a docType is not a trust decision: identity lives in the
    # certificate subject, so this string is only a document-type label. What
    # it does require is a document signer, because a conformant docType embeds
    # no issuer address and the chain is then the only way to resolve one.
    field :doc_type, :string

    # ISO pairs docType `org.iso.18013.5.1.mDL` with namespace
    # `org.iso.18013.5.1`. Null means "same as the docType", which is what a
    # generated schema means.
    field :namespace, :string

    belongs_to :issuer, Sovra.Workspaces.Workspace

    timestamps(type: :utc_datetime)
  end

  @required ~w(schema_id issuer_id credential_type name claims)a

  # Optional, but validated whenever the key is given: parse_validity_period/1
  # falls back to a year on anything it cannot read, so "1yr" would silently
  # become a real date. Zero is rejected too — "0d" puts `exp` at issuance, dead
  # on arrival.
  @validity_period ~r/^[1-9]\d*(y|m|d)$/

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ [:version, :kind, :format, :doc_type, :namespace])
    # Cast on its own with `empty_values: []` so a blank period reaches
    # validate_format/3. Ecto's default treats "" — and any whitespace-only
    # string — as empty and casts it to the field default, recording no change:
    # validate_format/3 would never run and the schema would read as an explicit
    # "no expiry", which is the one thing nil is not allowed to be guessed for.
    |> cast(attrs, [:validity_period], empty_values: [])
    |> validate_required(@required)
    |> validate_format(:validity_period, @validity_period)
    |> validate_inclusion(:kind, @kinds)
    |> validate_inclusion(:format, @formats)
    |> validate_mdoc_schema_id()
    |> validate_doc_type()
    |> validate_iso_elements()
    |> check_constraint(:format,
      name: :credential_schemas_mdoc_kind_check,
      message: "mdoc is only available for credential schemas"
    )
    |> unique_constraint([:issuer_id, :schema_id, :version])
  end

  # The schema_id becomes a docType segment, so for mdoc it has to stay inside
  # the reverse-DNS alphabet — a dot in the schema_id would silently add a
  # level to the docType. Conditional on the format so existing sd-jwt
  # schema_ids are not retro-invalidated.
  defp validate_mdoc_schema_id(changeset) do
    case get_field(changeset, :format) do
      "mso_mdoc" ->
        validate_format(changeset, :schema_id, ~r/^[a-z0-9][a-z0-9_-]*$/,
          message: "must be lowercase alphanumeric, - or _ (it becomes part of the docType)"
        )

      _ ->
        changeset
    end
  end

  # A docType and a namespace are reverse-DNS labels, and only meaningful for
  # mdoc. Letting an sd-jwt schema carry one would be a field that silently does
  # nothing, which is worse than a rejection.
  #
  # Case-sensitive, and mixed case is allowed: ISO's own document type is
  # `org.iso.18013.5.1.mDL`. These look like hostnames but are not — nothing
  # resolves them, and no reader lowercases one before comparing, so `mdl` and
  # `mDL` are two different document types and the rule must not pretend
  # otherwise. `Sovra.Mdoc.DocType.issuer_address/1` separately insists on the
  # lowercase form for the docTypes *we* generate, which is a different rule
  # about a different string.
  @reverse_dns ~r/^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)+$/

  defp validate_doc_type(changeset) do
    changeset =
      if get_field(changeset, :format) == "mso_mdoc" do
        changeset
        |> validate_format(:doc_type, @reverse_dns,
          message: "must be a reverse-DNS identifier, e.g. org.iso.18013.5.1.mDL"
        )
        |> validate_format(:namespace, @reverse_dns,
          message: "must be a reverse-DNS identifier, e.g. org.iso.18013.5.1"
        )
      else
        changeset
      end

    if get_field(changeset, :format) != "mso_mdoc" and
         (get_field(changeset, :doc_type) || get_field(changeset, :namespace)) do
      add_error(changeset, :doc_type, "is only meaningful for mso_mdoc schemas")
    else
      changeset
    end
  end

  # `org.iso.18013.5.1` is a closed element set, so a claim ISO does not define
  # cannot go in it — see `Sovra.Mdl.Template`. Every other namespace, including
  # an issuer's own extension namespace beside the ISO one, is left alone.
  defp validate_iso_elements(changeset) do
    claims = get_field(changeset, :claims) |> ClaimUtils.parse_claim_defs()

    case Template.validate(get_field(changeset, :namespace), claims) do
      :ok ->
        changeset

      {:error, {:undefined_iso_elements, keys}} ->
        add_error(
          changeset,
          :claims,
          "#{Enum.join(keys, ", ")}: not defined by #{Template.namespace()} — " <>
            "carry your own elements in your own namespace"
        )

      {:error, {:wrong_iso_element_type, keys}} ->
        add_error(
          changeset,
          :claims,
          "#{Enum.join(keys, ", ")}: not the type #{Template.namespace()} defines"
        )
    end
  end

  @doc """
  Asserts a workspace may issue under this schema's docType.

  A generated docType carries the issuer's address, so a verifier can always
  resolve it. An operator-supplied one cannot, and the certificate chain is the
  only remaining route — so naming your own requires a registered document
  signer. Checked here rather than in the changeset because it depends on the
  workspace, which a schema changeset does not see.
  """
  def assert_can_issue(%__MODULE__{doc_type: doc_type}, workspace)
      when is_binary(doc_type) and doc_type != "" do
    if Sovra.Mdl.can_issue_iso_doc_types?(workspace),
      do: :ok,
      else: {:error, :document_signer_required}
  end

  def assert_can_issue(%__MODULE__{}, _workspace), do: :ok

  def kinds, do: @kinds

  def formats, do: @formats

  @doc """
  Asserts a schema is of the expected kind.

  A credential schema is issued to a wallet over OID4VCI; a document schema is
  signed directly by the issuer. Mixing the two flows is always a mistake, so
  both entry points assert rather than trusting the caller.
  """
  def assert_kind(%__MODULE__{kind: kind}, kind), do: :ok
  def assert_kind(%__MODULE__{kind: kind}, _expected), do: {:error, {:wrong_schema_kind, kind}}

  @doc """
  Asserts a schema is of the expected wire format.

  The sibling of `assert_kind/2`, for entry points that can only handle one
  serialization — an SD-JWT parser handed an mdoc fails in ways that are much
  harder to read than this.
  """
  def assert_format(%__MODULE__{format: format}, format), do: :ok

  def assert_format(%__MODULE__{format: format}, _expected),
    do: {:error, {:wrong_schema_format, format}}
end
