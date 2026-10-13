defmodule Sovra.Accounts do
  @moduledoc """
  User accounts: registration, authentication, lookup, password updates.

  A registration creates the user, a default organization with the user as
  owner, and a default workspace. Tokens (access + refresh) are minted by the
  caller.
  """

  use Sovra.Log

  import Ecto.Query

  alias Sovra.Accounts.User
  alias Sovra.Auth.MailerJob
  alias Sovra.Organizations
  alias Sovra.Organizations.Organization
  alias Sovra.Repo
  alias Sovra.Workspaces

  @doc """
  Register a new user. Creates a default organization (with the user as
  owner) and a default workspace. Returns the created records.

  Required keys: `:email`, `:password`, `:full_name`.
  Optional: `:workspace_name` (defaults to "<full_name>'s workspace").
  """
  def register_user(attrs) do
    email = Map.get(attrs, :email) || Map.get(attrs, "email")
    password = Map.get(attrs, :password) || Map.get(attrs, "password")
    full_name = Map.get(attrs, :full_name) || Map.get(attrs, "full_name")
    workspace_name = Map.get(attrs, :workspace_name) || Map.get(attrs, "workspace_name")
    workspace_name = workspace_name || "#{full_name}'s workspace"
    org_name = workspace_name

    Repo.transaction(fn ->
      with {:ok, organization} <-
             %{name: org_name} |> Organization.create_changeset() |> Repo.insert(),
           {:ok, user} <-
             %{email: email, password: password, full_name: full_name}
             |> User.registration_changeset()
             |> Repo.insert(),
           {:ok, _org_mem} <- Organizations.add_member(organization.id, user.id, "owner"),
           {:ok, %{workspace: workspace}} <-
             Workspaces.create_workspace(
               organization.id,
               %{name: workspace_name},
               user.id
             ) do
        %{
          user: user,
          workspace: workspace,
          organization: organization
        }
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, %{user: user, workspace: workspace} = result} ->
        enqueue_email(%{kind: "welcome", user_id: user.id, workspace_name: workspace.name})
        {:ok, result}

      other ->
        other
    end
  end

  defp enqueue_email(args) do
    case args |> Log.job_args() |> MailerJob.new() |> Oban.insert() do
      {:ok, _job} ->
        :ok

      {:error, reason} ->
        Log.event(:error, "auth email enqueue failed",
          event: "email.enqueue_failed",
          kind: args[:kind] || args["kind"],
          reason: Log.reason(reason)
        )

        :ok
    end
  end

  def create_admin(attrs) do
    attrs
    |> User.admin_changeset()
    |> Repo.insert()
  end

  @doc "Authenticate by email + password. Returns the user record on success."
  def authenticate(email, password) when is_binary(email) and is_binary(password) do
    # Email column is citext: equality is case-insensitive at the DB layer,
    # so no need to downcase the input here.
    user = Repo.one(from(u in User, where: u.email == ^email))

    cond do
      user && Bcrypt.verify_pass(password, user.password_hash) ->
        {:ok, user}

      user ->
        {:error, :invalid_credentials}

      true ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
    end
  end

  def get_user(id), do: Repo.get(User, id)

  def get_user_by_email(email) when is_binary(email) do
    Repo.one(from(u in User, where: u.email == ^email))
  end

  def update_password(%User{} = user, password) do
    user
    |> User.password_changeset(%{password: password})
    |> Repo.update()
  end
end
