defmodule Sovra.Webhooks.Webhook do
  @moduledoc """
  One destination for a workspace's events: a URL, the event types it is
  subscribed to, and its own HMAC signing secret (referenced by
  `secret_key_id` in `Sovra.Crypto.HmacKeyStore`).

  `events` is an explicit list, never a wildcard: an event type added to the
  catalogue later reaches an endpoint only once an operator subscribes it, so a
  receiver is never handed a payload shape it was not written for.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workspace_webhooks" do
    field :url, :string
    field :events, {:array, :string}
    field :enabled, :boolean, default: true
    field :secret_key_id, :string

    belongs_to :workspace, Sovra.Workspaces.Workspace

    timestamps(type: :utc_datetime)
  end

  @url_regex ~r|^https?://[^\s]+$|

  @doc """
  `workspace_id` and `secret_key_id` are set on the struct by the caller, never
  cast: neither is something a client chooses.
  """
  def create_changeset(%__MODULE__{} = record, attrs) do
    record
    |> cast(attrs, [:url, :events, :enabled])
    |> validate_required([:url, :events, :workspace_id, :secret_key_id])
    |> validate_fields()
    |> foreign_key_constraint(:workspace_id)
    |> unique_constraint(:secret_key_id)
  end

  def update_changeset(%__MODULE__{} = record, attrs) do
    record
    |> cast(attrs, [:url, :events, :enabled])
    |> validate_required([:url, :events, :enabled])
    |> validate_fields()
  end

  defp validate_fields(changeset) do
    changeset
    |> validate_format(:url, @url_regex, message: "must be a valid http(s) URL")
    |> validate_length(:url, max: 2048)
    |> update_change(:events, &Enum.uniq/1)
    |> validate_length(:events, min: 1, message: "must include at least one event type")
    |> validate_subset(:events, Sovra.Webhooks.event_types())
    |> check_constraint(:events, name: :workspace_webhooks_events_not_empty)
  end
end
