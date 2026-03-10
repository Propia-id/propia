defmodule Sovra.Issuer.IssuerAccount do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "issuer_accounts" do
    field :email, :string
    field :password, :string, virtual: true, redact: true
    field :password_hash, :string, redact: true

    belongs_to :issuer, Sovra.Issuer.IssuerRecord

    timestamps(type: :utc_datetime)
  end

  def registration_changeset(account \\ %__MODULE__{}, attrs) do
    account
    |> cast(attrs, [:email, :password, :issuer_id])
    |> validate_required([:email, :password, :issuer_id])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> validate_length(:password, min: 12, message: "must be at least 12 characters")
    |> unique_constraint(:email)
    |> unique_constraint(:issuer_id)
    |> put_password_hash()
  end

  defp put_password_hash(%{valid?: true, changes: %{password: password}} = changeset) do
    put_change(changeset, :password_hash, Bcrypt.hash_pwd_salt(password))
  end

  defp put_password_hash(changeset), do: changeset
end
