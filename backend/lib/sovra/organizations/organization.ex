defmodule Sovra.Organizations.Organization do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @url_regex ~r|^https?://[^\s]+$|

  schema "organizations" do
    field :name, :string
    field :logo_url, :string
    field :website, :string
    field :status, :string, default: "active"

    has_many :members, Sovra.Organizations.OrganizationMember
    has_many :workspaces, Sovra.Workspaces.Workspace

    timestamps(type: :utc_datetime)
  end

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, [:name, :logo_url, :website])
    |> validate_required([:name])
    |> validate_length(:name, min: 1, max: 200)
    |> validate_url(:logo_url)
    |> validate_url(:website)
  end

  def update_changeset(record, attrs) do
    if record.status == "deactivated" do
      record
      |> change()
      |> add_error(:status, "cannot update a deactivated organization")
    else
      record
      |> cast(attrs, [:name, :logo_url, :website])
      |> validate_length(:name, min: 1, max: 200)
      |> validate_url(:logo_url)
      |> validate_url(:website)
    end
  end

  def status_changeset(record, status) do
    record
    |> change(status: status)
    |> validate_inclusion(:status, ~w(active suspended deactivated))
  end

  defp validate_url(changeset, field) do
    validate_format(changeset, field, @url_regex, message: "must be a valid http(s) URL")
  end
end
