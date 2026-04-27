defmodule Sovra.Workspaces.Workspace do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workspaces" do
    field :name, :string
    field :eoa_address, :string
    field :eoa_key_id, :string
    field :signing_key_id, :string
    field :signing_public_key_x, :binary
    field :signing_public_key_y, :binary
    field :did, :string
    field :status, :string, default: "active"
    field :webhook_url, :string
    field :webhook_secret_key_id, :string

    belongs_to :organization, Sovra.Organizations.Organization

    timestamps(type: :utc_datetime)
  end

  @required ~w(name eoa_address eoa_key_id signing_key_id signing_public_key_x signing_public_key_y did organization_id)a

  @url_regex ~r|^https?://[^\s]+$|

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ [:webhook_url, :webhook_secret_key_id])
    |> validate_required(@required)
    |> validate_url(:webhook_url)
    |> unique_constraint(:eoa_address)
    |> unique_constraint(:did)
    |> foreign_key_constraint(:organization_id)
  end

  def update_changeset(record, attrs) do
    if record.status == "deactivated" do
      record
      |> change()
      |> add_error(:status, "cannot update a deactivated workspace")
    else
      record
      |> cast(attrs, [:name, :webhook_url])
      |> validate_length(:name, min: 1, max: 200)
      |> validate_url(:webhook_url)
    end
  end

  def webhook_secret_changeset(record, key_id) do
    change(record, webhook_secret_key_id: key_id)
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
