defmodule Sovra.Issuer.IssuedCredential do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "issued_credentials" do
    field :holder_did, :string
    field :status, :string, default: "issued"
    field :status_list_index, :integer
    field :status_purpose, :string, default: "revocation"
    field :issued_at, :utc_datetime
    field :expires_at, :utc_datetime

    belongs_to :issuer, Sovra.Issuer.IssuerRecord
    belongs_to :schema, Sovra.Issuer.CredentialSchema

    timestamps(type: :utc_datetime)
  end

  @required ~w(issuer_id schema_id holder_did issued_at expires_at)a
  @optional ~w(status_list_index status_purpose)a

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
  end

  def status_changeset(record, status) do
    record
    |> change(status: status)
    |> validate_inclusion(:status, ~w(issued revoked suspended))
  end
end
