defmodule Sovra.Issuer.CredentialOffer do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "credential_offers" do
    field :holder_did, :string
    field :pre_authorized_code, :string
    field :tx_code, :string
    field :access_token, :string
    field :c_nonce, :string
    field :claims, :map
    field :status, :string, default: "pending"
    field :sd_jwt, :string
    field :expires_at, :utc_datetime

    belongs_to :issuer, Sovra.Issuer.IssuerRecord
    belongs_to :schema, Sovra.Issuer.CredentialSchema

    timestamps(type: :utc_datetime)
  end

  @required ~w(issuer_id schema_id holder_did pre_authorized_code claims sd_jwt expires_at)a

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ [:tx_code])
    |> validate_required(@required)
    |> unique_constraint(:pre_authorized_code)
    |> unique_constraint(:access_token)
  end

  def token_exchanged_changeset(record, attrs) do
    record
    |> cast(attrs, [:access_token, :c_nonce])
    |> validate_required([:access_token, :c_nonce])
    |> change(status: "token_exchanged")
    |> unique_constraint(:access_token)
  end

  def issued_changeset(record) do
    record
    |> change(status: "issued", claims: nil)
  end
end
