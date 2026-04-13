defmodule Sovra.Crypto.StoredKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "stored_keys" do
    field :key_id, :string
    field :private_key, :binary
    field :holder_id, :string

    timestamps(type: :utc_datetime)
  end

  def changeset(stored_key \\ %__MODULE__{}, attrs) do
    stored_key
    |> cast(attrs, [:key_id, :private_key, :holder_id])
    |> validate_required([:key_id, :private_key])
    |> unique_constraint(:key_id)
  end
end
