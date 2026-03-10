defmodule Sovra.Issuer.IssuerRecord do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "issuers" do
    field :name, :string
    field :eoa_address, :string
    field :eoa_key_id, :string
    field :signing_key_id, :string
    field :signing_public_key_x, :binary
    field :signing_public_key_y, :binary
    field :did, :string
    field :status, :string, default: "active"

    timestamps(type: :utc_datetime)
  end

  @required ~w(name eoa_address eoa_key_id signing_key_id signing_public_key_x signing_public_key_y did)a

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required)
    |> validate_required(@required)
    |> unique_constraint(:eoa_address)
    |> unique_constraint(:did)
  end

  def status_changeset(record, status) do
    record
    |> change(status: status)
    |> validate_inclusion(:status, ~w(active suspended deactivated))
  end
end
