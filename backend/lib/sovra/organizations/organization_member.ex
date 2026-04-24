defmodule Sovra.Organizations.OrganizationMember do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "organization_members" do
    field :organization_id, :binary_id, primary_key: true
    field :user_id, :binary_id, primary_key: true
    field :role, :string, default: "member"

    belongs_to :organization, Sovra.Organizations.Organization, define_field: false
    belongs_to :user, Sovra.Issuer.IssuerAccount, define_field: false

    timestamps(type: :utc_datetime)
  end

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, [:organization_id, :user_id, :role])
    |> validate_required([:organization_id, :user_id, :role])
    |> validate_inclusion(:role, ~w(owner admin member))
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:user_id)
  end

  def role_changeset(record, role) do
    record
    |> change(role: role)
    |> validate_inclusion(:role, ~w(owner admin member))
  end
end
