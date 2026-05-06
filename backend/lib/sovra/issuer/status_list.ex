defmodule Sovra.Issuer.StatusList do
  @moduledoc """
  Per-(workspace, status_purpose) row tracking the current HMAC truncation
  width used by the status-index allocator.

  Width starts at `initial_width/0` (17 → 131,072 slots — the W3C herd-privacy
  minimum) and is bumped by 1 each time the allocator exhausts retries at the
  current width. Capped at `max_width/0` (30 → ~10⁹ slots).

  Row's primary key is composite `(workspace_id, status_purpose)`.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @initial_width 17
  @max_width 30

  @primary_key false
  @foreign_key_type :binary_id

  schema "status_lists" do
    field :workspace_id, :binary_id, primary_key: true
    field :status_purpose, :string, primary_key: true
    field :width, :integer, default: @initial_width

    belongs_to :workspace, Sovra.Workspaces.Workspace, define_field: false

    timestamps(type: :utc_datetime)
  end

  def initial_width, do: @initial_width
  def max_width, do: @max_width

  def create_changeset(attrs) do
    %__MODULE__{}
    |> cast(attrs, [:workspace_id, :status_purpose, :width])
    |> validate_required([:workspace_id, :status_purpose])
    |> validate_number(:width, greater_than: 0, less_than_or_equal_to: @max_width)
  end

  def bump_width_changeset(%__MODULE__{width: width} = record) do
    record
    |> change(width: width + 1)
    |> validate_number(:width, greater_than: 0, less_than_or_equal_to: @max_width)
  end
end
