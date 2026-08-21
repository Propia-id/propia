defmodule Sovra.Auth.IssuerInvitation do
  @moduledoc """
  An authorization for one email address to create an issuer account.

  Carries two secrets, stored only as SHA-256: the emailed link token, and
  the short code sent to `email` when the invitee submits the form.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "issuer_invitations" do
    field :email, :string
    field :token_hash, :string, redact: true
    field :invited_by_user_id, :binary_id
    field :expires_at, :utc_datetime
    field :used_at, :utc_datetime
    field :revoked_at, :utc_datetime
    field :code_hash, :string, redact: true
    field :code_expires_at, :utc_datetime
    field :code_attempts, :integer, default: 0

    belongs_to :invited_by, Sovra.Accounts.User, define_field: false

    timestamps(type: :utc_datetime)
  end

  @create_fields ~w(email token_hash invited_by_user_id expires_at)a

  def create_changeset(attrs) do
    %__MODULE__{}
    |> cast(attrs, @create_fields)
    |> update_change(:email, &String.downcase/1)
    |> validate_required(~w(email token_hash expires_at)a)
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> unique_constraint(:token_hash)
    |> foreign_key_constraint(:invited_by_user_id)
  end

  @doc "Attach a freshly issued code, clearing any attempts spent on the previous one."
  def code_changeset(record, code_hash, %DateTime{} = expires_at) do
    change(record, code_hash: code_hash, code_expires_at: expires_at, code_attempts: 0)
  end

  def revoke_changeset(record, %DateTime{} = now) do
    change(record, revoked_at: now)
  end

  @doc "Pending means redeemable: never used, not revoked, not expired."
  def pending?(%__MODULE__{used_at: nil, revoked_at: nil, expires_at: expires_at}, now),
    do: DateTime.compare(expires_at, now) == :gt

  def pending?(%__MODULE__{}, _now), do: false
end
