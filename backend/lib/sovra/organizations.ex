defmodule Sovra.Organizations do
  @moduledoc """
  Organization lifecycle, membership, and branding.

  An organization is a top-level tenant that groups users and workspaces.
  Every user belongs to 0..N organizations via `organization_members`; roles
  inside an organization are `owner`, `admin`, `member`.
  """

  use Sovra.Log

  import Ecto.Query

  alias Sovra.Accounts.User
  alias Sovra.Organizations.{Organization, OrganizationMember}
  alias Sovra.Repo

  @doc """
  Whether the self-service organization-creation endpoint is open.

  Off by default (`:organization_creation_enabled` in config.exs). Only the HTTP
  action consults this — `create_organization/2` itself stays callable from
  registration, seeds, and tests.
  """
  @spec creation_enabled?() :: boolean()
  def creation_enabled? do
    Application.get_env(:sovra, :organization_creation_enabled, false) == true
  end

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
        # user_id is passed explicitly rather than read from the log context:
        # registration creates an organization before any session exists, so
        # there is no ambient actor on that path.
        Log.event(:info, "organization created",
          event: "org.created",
          org_id: org.id,
          owner_user_id: user_id
        )

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
    |> tap(fn
      {:ok, _} ->
        # Deactivation stops every workspace under the org from issuing, so it
        # is the first thing to check when a tenant reports a total outage.
        Log.event(:info, "organization deactivated",
          event: "org.deactivated",
          org_id: org.id,
          previous_status: org.status
        )

      {:error, _} ->
        :ok
    end)
  end

  @doc """
  Returns members of an organization with their role and a placeholder status.

  TODO: when the user-accounts issue introduces a status column on
  `users`, replace the literal with the real value.
  """
  def list_members(org_id) do
    from(m in OrganizationMember,
      join: u in User,
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
    |> tap(fn
      {:ok, _} ->
        Log.event(:info, "organization member added",
          event: "org.member.added",
          org_id: org_id,
          member_user_id: user_id,
          member_role: role
        )

      {:error, _} ->
        :ok
    end)
  end
end
