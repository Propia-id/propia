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

  import Ecto.Query

  def register_issuer(email, password, workspace_name) do
    Repo.transaction(fn ->
      with {:ok, organization} <-
             %{name: workspace_name} |> Organization.create_changeset() |> Repo.insert(),
           {:ok, account} <-
             %{email: email, password: password}
             |> IssuerAccount.registration_changeset()
             |> Repo.insert(),
           {:ok, _org_mem} <- Organizations.add_member(organization.id, account.id, "owner"),
           {:ok, %{workspace: workspace, webhook_secret: webhook_secret}} <-
             Workspaces.create_workspace(
               organization.id,
               %{name: workspace_name},
               account.id
             ) do
        {:ok, token} = IssuerSession.create(account.id, workspace.id, "issuer")

        %{
          token: token,
          account: account,
          workspace: workspace,
          organization: organization,
          webhook_secret: webhook_secret
        }
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
        workspaces = Workspaces.list_workspaces_for_user(account.id)
        current_workspace_id = workspaces |> List.first() |> get_id()

        {:ok, token} = IssuerSession.create(account.id, current_workspace_id, account.role)

        {:ok,
         %{
           token: token,
           account: account,
           role: account.role,
           workspaces: workspaces,
           current_workspace_id: current_workspace_id
         }}

      account ->
        {:error, :invalid_credentials}

      true ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
    end
  end

  defp get_id(nil), do: nil
  defp get_id(%{id: id}), do: id
end
