defmodule Sovra.Auth.RefreshToken do
  use Ecto.Schema

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "refresh_tokens" do
    field :user_id, :binary_id
    field :token_hash, :string, redact: true
    field :expires_at, :utc_datetime
    field :revoked_at, :utc_datetime
    field :last_used_at, :utc_datetime

    belongs_to :user, Sovra.Accounts.User, define_field: false

    timestamps(type: :utc_datetime)
  end
end
