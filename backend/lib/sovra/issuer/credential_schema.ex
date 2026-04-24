defmodule Sovra.Issuer.CredentialSchema do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "credential_schemas" do
    field :schema_id, :string
    field :credential_type, :string
    field :name, :string
    field :claims, {:array, :map}
    field :validity_period, :string
    field :version, :integer, default: 1

    belongs_to :issuer, Sovra.Workspaces.Workspace

    timestamps(type: :utc_datetime)
  end

  @required ~w(schema_id issuer_id credential_type name claims validity_period)a

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ [:version])
    |> validate_required(@required)
    |> unique_constraint([:issuer_id, :schema_id])
  end
end
