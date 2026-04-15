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
    field :expires_at, :utc_datetime

    belongs_to :issuer, Sovra.Issuer.IssuerRecord
    belongs_to :schema, Sovra.Issuer.CredentialSchema

    timestamps(type: :utc_datetime)
  end

  @required ~w(issuer_id schema_id pre_authorized_code_hash claims expires_at)a

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ [:tx_code])
    |> validate_required(@required)
    |> unique_constraint(:pre_authorized_code_hash)
    |> unique_constraint(:access_token_hash)
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
