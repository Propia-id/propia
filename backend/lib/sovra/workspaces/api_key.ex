defmodule Sovra.Workspaces.ApiKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workspace_api_keys" do
    field :name, :string
    field :api_key_hash, :string
    field :last_used_at, :utc_datetime
    field :revoked_at, :utc_datetime

    belongs_to :workspace, Sovra.Workspaces.Workspace

    timestamps(type: :utc_datetime)
  end

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, [:name, :workspace_id, :api_key_hash])
    |> validate_required([:name, :workspace_id, :api_key_hash])
    |> validate_length(:name, min: 1, max: 100)
    |> unique_constraint(:api_key_hash)
    |> foreign_key_constraint(:workspace_id)
  end

  def touch_used_changeset(record) do
    change(record, last_used_at: DateTime.utc_now() |> DateTime.truncate(:second))
  end

  def revoke_changeset(record) do
    change(record, revoked_at: DateTime.utc_now() |> DateTime.truncate(:second))
  end
end
