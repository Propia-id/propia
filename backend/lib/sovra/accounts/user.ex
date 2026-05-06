defmodule Sovra.Accounts.User do
  @moduledoc """
  Authenticated principal for the platform — used by issuer-console
  operators today and by other personas (verifiers, etc.) in the future.

  `is_admin` is the *system* (super-admin) flag, distinct from per-org
  and per-workspace roles which live on the membership join tables
  (`organization_members.role`, `workspace_members.role`). Don't conflate
  them: a system admin has no implicit access to an org or workspace.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "users" do
    field :email, :string
    field :full_name, :string
    field :password, :string, virtual: true, redact: true
    field :password_hash, :string, redact: true
    # System super-admin. NOT the same as org/workspace membership role.
    field :is_admin, :boolean, default: false

    timestamps(type: :utc_datetime)
  end

  def registration_changeset(user \\ %__MODULE__{}, attrs) do
    user
    |> cast(attrs, [:email, :password, :full_name])
    |> update_change(:email, &String.downcase/1)
    |> validate_required([:email, :password, :full_name])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> validate_length(:full_name, min: 1, max: 200)
    |> validate_length(:password, min: 12, message: "must be at least 12 characters")
    |> unique_constraint(:email)
    |> put_change(:is_admin, false)
    |> put_password_hash()
  end

  def admin_changeset(user \\ %__MODULE__{}, attrs) do
    user
    |> cast(attrs, [:email, :password, :full_name])
    |> update_change(:email, &String.downcase/1)
    |> validate_required([:email, :password])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/, message: "must be a valid email")
    |> validate_length(:full_name, max: 200)
    |> validate_length(:password, min: 12, message: "must be at least 12 characters")
    |> unique_constraint(:email)
    |> put_change(:is_admin, true)
    |> backfill_full_name_from_email()
    |> put_password_hash()
  end

  def password_changeset(user, attrs) do
    user
    |> cast(attrs, [:password])
    |> validate_required([:password])
    |> validate_length(:password, min: 12, message: "must be at least 12 characters")
    |> put_password_hash()
  end

  defp backfill_full_name_from_email(%{valid?: true, changes: changes} = changeset) do
    case Map.get(changes, :full_name) do
      nil ->
        case Map.get(changes, :email) || changeset.data.email do
          nil -> changeset
          email -> put_change(changeset, :full_name, email |> String.split("@") |> hd())
        end

      _ ->
        changeset
    end
  end

  defp backfill_full_name_from_email(changeset), do: changeset

  defp put_password_hash(%{valid?: true, changes: %{password: password}} = changeset) do
    put_change(changeset, :password_hash, Bcrypt.hash_pwd_salt(password))
  end

  defp put_password_hash(changeset), do: changeset
end
