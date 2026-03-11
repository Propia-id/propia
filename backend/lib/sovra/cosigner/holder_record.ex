defmodule Sovra.Cosigner.HolderRecord do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "holder_records" do
    field :sovra_address, :string
    field :recovery_key_id, :string
    field :recovery_public_key_x, :binary
    field :recovery_public_key_y, :binary
    field :oauth_provider, :string
    field :oauth_subject, :string
    field :status, :string, default: "active"

    timestamps(type: :utc_datetime)
  end

  @required ~w(sovra_address recovery_key_id recovery_public_key_x recovery_public_key_y oauth_provider oauth_subject)a

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required)
    |> validate_required(@required)
    |> validate_inclusion(:status, ~w(active recovery_pending deactivated))
    |> unique_constraint(:sovra_address)
    |> unique_constraint([:oauth_provider, :oauth_subject])
  end

  def status_changeset(record, status) do
    record
    |> change(status: status)
    |> validate_inclusion(:status, ~w(active recovery_pending deactivated))
  end

  def update_key_changeset(record, attrs) do
    record
    |> cast(attrs, [:recovery_key_id, :recovery_public_key_x, :recovery_public_key_y])
    |> validate_required([:recovery_key_id, :recovery_public_key_x, :recovery_public_key_y])
  end
end
