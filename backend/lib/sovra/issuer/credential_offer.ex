defmodule Sovra.Issuer.CredentialOffer do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "credential_offers" do
    field :pre_authorized_code_hash, :string
    field :tx_code, :string
    field :access_token_hash, :string
    field :c_nonce, :string
    field :claims, :map
    field :status, :string, default: "pending"
    field :status_list_index, :integer
    field :status_purpose, :string, default: "revocation"
    # The offer's own pickup window. `credential_valid_until` is the credential's.
    field :expires_at, :utc_datetime
    field :credential_valid_until, :utc_datetime

    belongs_to :issuer, Sovra.Workspaces.Workspace
    belongs_to :schema, Sovra.Issuer.CredentialSchema

    timestamps(type: :utc_datetime)
  end

  @required ~w(issuer_id schema_id pre_authorized_code_hash claims expires_at)a
  @optional ~w(id tx_code status_list_index status_purpose credential_valid_until)a

  @status_index_constraint :credential_offers_status_index_purpose_idx

  @doc "Constraint name used by `unique_constraint(:status_list_index, ...)` — exposed so the allocator can pin its retry-on-collision detection to this exact constraint."
  def status_index_constraint, do: @status_index_constraint

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> unique_constraint(:pre_authorized_code_hash)
    |> unique_constraint(:access_token_hash)
    |> unique_constraint(:status_list_index, name: @status_index_constraint)
  end

  def token_exchanged_changeset(record, attrs) do
    record
    |> cast(attrs, [:access_token_hash, :c_nonce])
    |> validate_required([:access_token_hash, :c_nonce])
    |> change(status: "token_exchanged")
    |> unique_constraint(:access_token_hash)
  end

  def issued_changeset(record) do
    record
    |> change(
      status: "issued",
      claims: nil,
      pre_authorized_code_hash: nil,
      access_token_hash: nil
    )
  end
end
