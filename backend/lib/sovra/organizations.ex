defmodule Sovra.Organizations do
  @moduledoc """
  Organization lifecycle, membership, and branding.

  An organization is a top-level tenant that groups users and workspaces.
  Every user belongs to 0..N organizations via `organization_members`; roles
  inside an organization are `owner`, `admin`, `member`.
  """

  import Ecto.Query

  alias Sovra.Organizations.{Organization, OrganizationMember}
  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Repo

  def create_organization(user_id, attrs) do
    org_changeset = Organization.create_changeset(attrs)

    Ecto.Multi.new()
    |> Ecto.Multi.insert(:organization, org_changeset)
    |> Ecto.Multi.insert(:membership, fn %{organization: org} ->
      OrganizationMember.create_changeset(%{
        organization_id: org.id,
        user_id: user_id,
        role: "owner"
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{organization: org, membership: mem}} ->
        {:ok, %{organization: org, membership: mem}}

      {:error, :organization, changeset, _} ->
        {:error, changeset}

      {:error, :membership, changeset, _} ->
        {:error, changeset}
    end
  end

  def get_organization(org_id) do
    case Repo.get(Organization, org_id) do
      nil -> {:error, :not_found}
      org -> {:ok, org}
    end
  end

  def list_organizations_for_user(user_id) do
    from(o in Organization,
      join: m in OrganizationMember,
      on: m.organization_id == o.id,
      where: m.user_id == ^user_id,
      order_by: [asc: o.name],
      select: %{
        id: o.id,
        name: o.name,
        logo_url: o.logo_url,
        website: o.website,
        status: o.status,
        role: m.role
      }
    )
    |> Repo.all()
  end

  def update_organization(%Organization{} = org, attrs) do
    org
    |> Organization.update_changeset(attrs)
    |> Repo.update()
  end

  def deactivate_organization(%Organization{} = org) do
    org
    |> Organization.status_changeset("deactivated")
    |> Repo.update()
  end

  @doc """
  Returns members of an organization with their role and a placeholder status.

  TODO: when the user-accounts issue introduces a status column on
  `issuer_accounts`, replace the literal with the real value.
  """
  def list_members(org_id) do
    from(m in OrganizationMember,
      join: u in IssuerAccount,
      on: u.id == m.user_id,
      where: m.organization_id == ^org_id,
      order_by: [asc: u.email],
      select: %{id: u.id, email: u.email, role: m.role, status: "active"}
    )
    |> Repo.all()
  end

  def member_role(org_id, user_id) do
    case Repo.get_by(OrganizationMember, organization_id: org_id, user_id: user_id) do
      nil -> {:error, :not_a_member}
      %OrganizationMember{role: role} -> {:ok, role}
    end
  end

  def add_member(org_id, user_id, role) do
    OrganizationMember.create_changeset(%{
      organization_id: org_id,
      user_id: user_id,
      role: role
    })
    |> Repo.insert()
  end
end
