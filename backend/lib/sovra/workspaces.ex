defmodule Sovra.Workspaces do
  @moduledoc """
  Workspace lifecycle — per-tenant operational units that act as credential
  issuers. Each workspace owns its DID, signing keys, and on-chain EOA, plus a
  webhook URL, a webhook secret (stored in the HMAC key store), and one or more
  API keys (managed via `Sovra.Workspaces.ApiKeys`).

  Workspaces always belong to an organization. Users belong to workspaces via
  the `workspace_members` join table with role `admin` or `member`.
  """

  import Ecto.Query

  alias Sovra.Accounts.User
  alias Sovra.Crypto.HmacKeyStore
  alias Sovra.Issuer.StatusList
  alias Sovra.Repo
  alias Sovra.Workspaces.Workspace
  alias Sovra.Workspaces.WorkspaceMember
  alias Sovra.Workspaces.WorkspaceProvisioningJob

  require Logger

  @doc """
  Create a workspace under an organization with `owner_user_id` as the
  founding admin member. Generates a webhook HMAC secret via the configured
  store — the plaintext is returned **exactly once** so the caller can reveal
  it to the user.

  The signing key, EOA, DID, and on-chain registration are produced
  asynchronously by `Sovra.Workspaces.WorkspaceProvisioningJob`. The
  workspace is returned with `provisioning_status: "pending"` and nil
  cryptographic fields; it transitions to `"done"` (or `"failed"`) once the
  provisioning job runs.
  """
  def create_workspace(organization_id, attrs, owner_user_id) do
    name = Map.get(attrs, :name) || Map.get(attrs, "name")
    webhook_url = Map.get(attrs, :webhook_url) || Map.get(attrs, "webhook_url")

    with {:ok, %{key_id: webhook_key_id, plaintext: webhook_secret}} <-
           HmacKeyStore.generate_hmac_key(),
         {:ok, %{key_id: status_index_key_id}} <- HmacKeyStore.generate_hmac_key() do
      changeset =
        Workspace.create_changeset(%{
          name: name,
          organization_id: organization_id,
          webhook_url: webhook_url,
          webhook_secret_key_id: webhook_key_id,
          status_index_secret_key_id: status_index_key_id
        })

      Ecto.Multi.new()
      |> Ecto.Multi.insert(:workspace, changeset)
      |> Ecto.Multi.insert(:owner_member, fn %{workspace: ws} ->
        WorkspaceMember.create_changeset(%{
          workspace_id: ws.id,
          user_id: owner_user_id,
          role: "admin"
        })
      end)
      |> Ecto.Multi.insert(:status_list_revocation, fn %{workspace: ws} ->
        StatusList.create_changeset(%{workspace_id: ws.id, status_purpose: "revocation"})
      end)
      |> Ecto.Multi.insert(:status_list_suspension, fn %{workspace: ws} ->
        StatusList.create_changeset(%{workspace_id: ws.id, status_purpose: "suspension"})
      end)
      |> Oban.insert(:provisioning_job, fn %{workspace: ws} ->
        WorkspaceProvisioningJob.new(%{workspace_id: ws.id})
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{workspace: workspace}} ->
          {:ok, %{workspace: workspace, webhook_secret: webhook_secret}}

        {:error, _step, changeset, _} ->
          {:error, changeset}
      end
    end
  end

  @doc """
  Mark a workspace's provisioning as complete. Called by the provisioning
  job once keys, DID, and on-chain registration have all succeeded. The
  cryptographic fields must already be persisted on the row by earlier
  steps of the job; this only flips the status, sets `provisioned_at`, and
  clears any prior error.
  """
  def mark_provisioning_done(workspace_id, %DateTime{} = provisioned_at) do
    with {:ok, workspace} <- get_workspace(workspace_id) do
      workspace
      |> Workspace.provisioning_done_changeset(%{
        eoa_address: workspace.eoa_address,
        eoa_key_id: workspace.eoa_key_id,
        signing_key_id: workspace.signing_key_id,
        signing_public_key_x: workspace.signing_public_key_x,
        signing_public_key_y: workspace.signing_public_key_y,
        did: workspace.did,
        provisioned_at: provisioned_at
      })
      |> Repo.update()
    end
  end

  @doc """
  Mark a workspace's provisioning as permanently failed with a free-form
  error reason. Called by the provisioning job after Oban exhausts all
  attempts.
  """
  def mark_provisioning_failed(workspace_id, error) when is_binary(error) do
    with {:ok, workspace} <- get_workspace(workspace_id) do
      workspace
      |> Workspace.provisioning_failed_changeset(error)
      |> Repo.update()
    end
  end

  @doc """
  Reset a `failed` workspace to `pending` and re-enqueue its provisioning
  job. The workspace must belong to `organization_id` (tenancy enforced
  here so HTTP plugs can stay generic).

  Returns:
  - `{:ok, workspace}` when re-enqueued.
  - `{:error, :workspace_not_found}` when the id doesn't exist or doesn't
    belong to the organization.
  - `{:error, :already_pending}` / `{:error, :already_provisioned}` when
    the row isn't in `failed`.
  - `{:error, :organization_deactivated}` when the parent organization has
    been deactivated.
  """
  def retry_provisioning(workspace_id, organization_id) do
    case Repo.get(Workspace, workspace_id) do
      nil ->
        {:error, :workspace_not_found}

      %Workspace{organization_id: org_id} when org_id != organization_id ->
        {:error, :workspace_not_found}

      %Workspace{provisioning_status: "pending"} ->
        {:error, :already_pending}

      %Workspace{provisioning_status: "done"} ->
        {:error, :already_provisioned}

      %Workspace{provisioning_status: "failed"} = workspace ->
        with :ok <- ensure_org_active(workspace.organization_id) do
          Ecto.Multi.new()
          |> Ecto.Multi.update(:workspace, Workspace.provisioning_retry_changeset(workspace))
          |> Oban.insert(:provisioning_job, fn %{workspace: ws} ->
            WorkspaceProvisioningJob.new(%{workspace_id: ws.id})
          end)
          |> Repo.transaction()
          |> case do
            {:ok, %{workspace: ws}} -> {:ok, ws}
            {:error, _step, reason, _} -> {:error, reason}
          end
        end
    end
  end

  defp ensure_org_active(organization_id) do
    case Repo.get(Sovra.Organizations.Organization, organization_id) do
      nil -> {:error, :workspace_not_found}
      %{status: "deactivated"} -> {:error, :organization_deactivated}
      _ -> :ok
    end
  end

  @doc """
  Guard for issuer/verifier mutating entry points: rejects workspaces that
  haven't completed async provisioning. Read flows (listings, lookups)
  should not call this — they keep working pre-provision.
  """
  def assert_provisioned(%Workspace{provisioning_status: "done"}), do: :ok
  def assert_provisioned(%Workspace{}), do: {:error, :workspace_not_provisioned}

  def get_workspace(id) do
    case Repo.get(Workspace, id) do
      nil -> {:error, :workspace_not_found}
      workspace -> {:ok, workspace}
    end
  end

  @doc """
  Loads a workspace and verifies that both the workspace and its parent
  organization are active. Returns `{:ok, workspace}` (with `:organization`
  preloaded), or `{:error, :workspace_not_found | :workspace_inactive |
  :organization_inactive}`. Use this from any admin-action context that needs
  to gate on tenant status.
  """
  def get_active_workspace(id) do
    with {:ok, workspace} <- get_workspace(id) do
      workspace = Repo.preload(workspace, :organization)

      cond do
        workspace.status != "active" ->
          {:error, :workspace_inactive}

        workspace.organization && workspace.organization.status != "active" ->
          {:error, :organization_inactive}

        true ->
          {:ok, workspace}
      end
    end
  end

  def get_workspace_by_did(did) when is_binary(did) do
    case Repo.get_by(Workspace, did: did) do
      nil -> {:error, :workspace_not_found}
      workspace -> {:ok, workspace}
    end
  end

  def list_workspaces do
    from(w in Workspace,
      order_by: [desc: w.inserted_at],
      select: %{id: w.id, name: w.name, did: w.did, status: w.status}
    )
    |> Repo.all()
  end

  def list_workspaces_for_organization(organization_id) do
    from(w in Workspace,
      where: w.organization_id == ^organization_id,
      order_by: [asc: w.name],
      select: %{
        id: w.id,
        name: w.name,
        did: w.did,
        status: w.status,
        provisioning_status: w.provisioning_status,
        provisioning_error: w.provisioning_error,
        provisioned_at: w.provisioned_at,
        organization_id: w.organization_id,
        webhook_url: w.webhook_url
      }
    )
    |> Repo.all()
  end

  def list_workspaces_for_user(user_id) do
    from(w in Workspace,
      join: m in WorkspaceMember,
      on: m.workspace_id == w.id,
      where: m.user_id == ^user_id,
      order_by: [asc: w.name],
      select: %{
        id: w.id,
        name: w.name,
        did: w.did,
        status: w.status,
        provisioning_status: w.provisioning_status,
        provisioning_error: w.provisioning_error,
        provisioned_at: w.provisioned_at,
        organization_id: w.organization_id,
        webhook_url: w.webhook_url,
        role: m.role
      }
    )
    |> Repo.all()
  end

  def get_first_workspace do
    case Repo.one(from(w in Workspace, where: w.status == "active", limit: 1)) do
      nil -> {:error, :no_workspaces}
      workspace -> {:ok, workspace}
    end
  end

  def update_workspace(%Workspace{} = workspace, attrs) do
    workspace
    |> Workspace.update_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Rotate the workspace's webhook HMAC secret. Returns the new plaintext
  exactly once.
  """
  def regenerate_webhook_secret(%Workspace{} = workspace) do
    case workspace.webhook_secret_key_id do
      nil ->
        with {:ok, %{key_id: key_id, plaintext: plaintext}} <- HmacKeyStore.generate_hmac_key(),
             {:ok, updated} <-
               workspace
               |> Workspace.webhook_secret_changeset(key_id)
               |> Repo.update() do
          {:ok, %{workspace: updated, webhook_secret: plaintext}}
        end

      key_id ->
        case HmacKeyStore.rotate(key_id) do
          {:ok, %{plaintext: plaintext}} ->
            {:ok, %{workspace: workspace, webhook_secret: plaintext}}

          {:error, _} = error ->
            error
        end
    end
  end

  # ── Membership ─────────────────────────────────────────

  def list_members(workspace_id) do
    from(m in WorkspaceMember,
      join: u in User,
      on: u.id == m.user_id,
      where: m.workspace_id == ^workspace_id,
      order_by: [asc: u.email],
      select: %{id: u.id, email: u.email, role: m.role, status: "active"}
    )
    |> Repo.all()
  end

  def member_role(workspace_id, user_id) do
    case Repo.get_by(WorkspaceMember, workspace_id: workspace_id, user_id: user_id) do
      nil -> {:error, :not_a_member}
      %WorkspaceMember{role: role} -> {:ok, role}
    end
  end

  def add_member(workspace_id, user_id, role) do
    WorkspaceMember.create_changeset(%{
      workspace_id: workspace_id,
      user_id: user_id,
      role: role
    })
    |> Repo.insert()
  end

  def update_member_role(workspace_id, user_id, new_role) do
    with %WorkspaceMember{} = member <-
           Repo.get_by(WorkspaceMember, workspace_id: workspace_id, user_id: user_id) ||
             {:error, :not_a_member},
         :ok <- ensure_not_last_admin_demotion(workspace_id, member, new_role) do
      member
      |> WorkspaceMember.role_changeset(new_role)
      |> Repo.update()
    end
  end

  def remove_member(workspace_id, user_id) do
    with %WorkspaceMember{} = member <-
           Repo.get_by(WorkspaceMember, workspace_id: workspace_id, user_id: user_id) ||
             {:error, :not_a_member},
         :ok <- ensure_not_last_admin_removal(workspace_id, member) do
      Repo.delete(member)
    end
  end

  defp ensure_not_last_admin_demotion(_workspace_id, %WorkspaceMember{role: "admin"}, "admin"),
    do: :ok

  defp ensure_not_last_admin_demotion(workspace_id, %WorkspaceMember{role: "admin"}, _new_role) do
    if count_admins(workspace_id) <= 1, do: {:error, :last_admin}, else: :ok
  end

  defp ensure_not_last_admin_demotion(_workspace_id, _member, _new_role), do: :ok

  defp ensure_not_last_admin_removal(workspace_id, %WorkspaceMember{role: "admin"}) do
    if count_admins(workspace_id) <= 1, do: {:error, :last_admin}, else: :ok
  end

  defp ensure_not_last_admin_removal(_workspace_id, _member), do: :ok

  defp count_admins(workspace_id) do
    from(m in WorkspaceMember,
      where: m.workspace_id == ^workspace_id and m.role == "admin",
      select: count()
    )
    |> Repo.one()
  end
end
