defmodule Sovra.Workspaces.Workspace do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workspaces" do
    field :name, :string
    field :eoa_address, :string
    field :eoa_key_id, :string
    field :signing_key_id, :string
    field :signing_public_key_x, :binary
    field :signing_public_key_y, :binary
    field :did, :string
    field :status, :string, default: "active"
    field :provisioning_status, :string, default: "pending"
    field :provisioning_error, :string
    field :provisioned_at, :utc_datetime
    field :webhook_url, :string
    field :webhook_secret_key_id, :string
    field :status_index_secret_key_id, :string

    # The mDL document signer: a dedicated KMS key, the certificate an issuing
    # authority issued for it, and the root that certificate chains to. Separate
    # from `signing_key_id` because ISO expects a document signer to rotate on
    # its own schedule — see `Sovra.Mdl`.
    field :mdl_signing_key_id, :string
    field :mdl_signing_public_key_x, :binary
    field :mdl_signing_public_key_y, :binary
    field :mdl_signer_certificate, :string

    belongs_to :organization, Sovra.Organizations.Organization
    belongs_to :mdl_issuing_authority, Sovra.Mdl.IssuingAuthority

    timestamps(type: :utc_datetime)
  end

  @create_required ~w(name organization_id webhook_secret_key_id status_index_secret_key_id)a
  @create_optional ~w(webhook_url)a

  @url_regex ~r|^https?://[^\s]+$|

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @create_required ++ @create_optional)
    |> validate_required(@create_required)
    |> validate_url(:webhook_url)
    |> foreign_key_constraint(:organization_id)
  end

  def update_changeset(record, attrs) do
    if record.status == "deactivated" do
      record
      |> change()
      |> add_error(:status, "cannot update a deactivated workspace")
    else
      record
      |> cast(attrs, [:name, :webhook_url])
      |> validate_length(:name, min: 1, max: 200)
      |> validate_url(:webhook_url)
    end
  end

  @mdl_key_fields ~w(mdl_signing_key_id mdl_signing_public_key_x mdl_signing_public_key_y)a

  @doc """
  Record the workspace's mDL document signer key.

  Separate from `mdl_signer_changeset/2` because the key exists first and alone:
  a certification request is built from it, and the certificate only arrives
  once the authority has signed one.
  """
  def mdl_signing_key_changeset(record, attrs) do
    record
    |> cast(attrs, @mdl_key_fields)
    |> validate_required(@mdl_key_fields)
  end

  @doc """
  Record the Document Signer Certificate and the root it chains to.

  Both together, never one: a certificate without its trust anchor is one no
  verifier of ours can do anything with. The database says the same thing in
  `workspaces_mdl_signer_complete_check`.
  """
  def mdl_signer_changeset(record, attrs) do
    record
    |> cast(attrs, ~w(mdl_signer_certificate mdl_issuing_authority_id)a)
    |> validate_required(~w(mdl_signer_certificate mdl_issuing_authority_id)a)
    |> foreign_key_constraint(:mdl_issuing_authority_id)
    |> check_constraint(:mdl_signer_certificate,
      name: :workspaces_mdl_signer_complete_check,
      message: "needs a signing key and an issuing authority"
    )
  end

  def webhook_secret_changeset(record, key_id) do
    change(record, webhook_secret_key_id: key_id)
  end

  def status_changeset(record, status) do
    record
    |> change(status: status)
    |> validate_inclusion(:status, ~w(active suspended deactivated))
  end

  @provisioning_done_fields ~w(eoa_address eoa_key_id signing_key_id signing_public_key_x signing_public_key_y did provisioned_at)a

  def provisioning_done_changeset(record, attrs) do
    record
    |> cast(attrs, @provisioning_done_fields)
    |> validate_required(@provisioning_done_fields)
    |> put_change(:provisioning_status, "done")
    |> put_change(:provisioning_error, nil)
    |> unique_constraint(:eoa_address)
    |> unique_constraint(:did)
  end

  def provisioning_progress_changeset(record, attrs) do
    record
    |> cast(attrs, @provisioning_done_fields -- [:provisioned_at])
    |> unique_constraint(:eoa_address)
    |> unique_constraint(:did)
  end

  def provisioning_failed_changeset(record, error) when is_binary(error) do
    record
    |> change(provisioning_status: "failed", provisioning_error: error)
  end

  def provisioning_retry_changeset(record) do
    record
    |> change(provisioning_status: "pending", provisioning_error: nil)
  end

  defp validate_url(changeset, field) do
    validate_format(changeset, field, @url_regex, message: "must be a valid http(s) URL")
  end
end
