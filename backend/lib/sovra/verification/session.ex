defmodule Sovra.Verification.Session do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(pending completed failed expired)

  schema "verification_sessions" do
    field :dcql_query, :map
    field :nonce, :string
    field :state, :string
    field :status, :string, default: "pending"
    field :holder_did, :string
    field :presentation_data, :map
    field :error, :string
    field :expires_at, :utc_datetime
    field :completed_at, :utc_datetime

    belongs_to :workspace, Sovra.Workspaces.Workspace

    timestamps(type: :utc_datetime)
  end

  @required ~w(workspace_id dcql_query nonce state expires_at)a

  def create_changeset(record \\ %__MODULE__{}, attrs) do
    record
    |> cast(attrs, @required ++ [:status])
    |> validate_required(@required)
    |> validate_inclusion(:status, @statuses)
    |> assoc_constraint(:workspace)
    |> unique_constraint(:state)
  end

  def complete_changeset(record, attrs) do
    record
    |> cast(attrs, [:holder_did, :presentation_data, :completed_at])
    |> validate_required([:holder_did, :presentation_data, :completed_at])
    |> change(status: "completed", error: nil)
  end

  def fail_changeset(record, attrs) do
    record
    |> cast(attrs, [:holder_did, :error, :completed_at])
    |> validate_required([:error, :completed_at])
    |> change(status: "failed")
  end
end
