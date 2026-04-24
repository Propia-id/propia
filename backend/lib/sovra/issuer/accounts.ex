defmodule Sovra.Issuer.Accounts do
  @moduledoc """
  Account management for issuer dashboard users.
  """

  alias Sovra.Auth.IssuerSession
  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Organizations
  alias Sovra.Organizations.Organization
  alias Sovra.Repo
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  import Ecto.Query

  def register_issuer(email, password, workspace_name) do
    Repo.transaction(fn ->
      with {:ok, organization} <-
             %{name: workspace_name} |> Organization.create_changeset() |> Repo.insert(),
           {:ok, workspace} <- Workspaces.create_workspace(workspace_name, organization.id),
           {:ok, account} <-
             %{email: email, password: password, workspace_id: workspace.id}
             |> IssuerAccount.registration_changeset()
             |> Repo.insert(),
           {:ok, _mem} <- Organizations.add_member(organization.id, account.id, "owner") do
        {:ok, token} = IssuerSession.create(account.id, workspace.id, "issuer")
        %{token: token, account: account, workspace: workspace, organization: organization}
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  def create_admin(email, password) do
    changeset = IssuerAccount.admin_changeset(%{email: email, password: password})

    case Repo.insert(changeset) do
      {:ok, account} -> {:ok, account}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def authenticate(email, password) do
    email = String.downcase(email)
    account = Repo.one(from(a in IssuerAccount, where: a.email == ^email))

    cond do
      account && Bcrypt.verify_pass(password, account.password_hash) ->
        {:ok, token} = IssuerSession.create(account.id, account.workspace_id, account.role)

        case account.role do
          "admin" ->
            {:ok, %{token: token, account: account, role: "admin"}}

          _ ->
            workspace = Repo.get!(Workspace, account.workspace_id)
            {:ok, %{token: token, account: account, workspace: workspace}}
        end

      account ->
        {:error, :invalid_credentials}

      true ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
    end
  end
end
