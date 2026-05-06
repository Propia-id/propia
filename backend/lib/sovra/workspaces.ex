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

  alias Sovra.Crypto.HmacKeyStore
  alias Sovra.Crypto.Key
  alias Sovra.Ethereum.DIDRegistry
  alias Sovra.Accounts.User
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.StatusList
  alias Sovra.Repo
  alias Sovra.Workspaces.Workspace
  alias Sovra.Workspaces.WorkspaceMember

  require Logger

  @doc """
  Create a workspace under an organization with `owner_user_id` as the
  founding admin member. Generates a webhook HMAC secret via the configured
  store — the plaintext is returned **exactly once** so the caller can reveal
  it to the user.
  """
  def create_workspace(organization_id, attrs, owner_user_id) do
    workspace_uuid = Ecto.UUID.generate()
    name = Map.get(attrs, :name) || Map.get(attrs, "name")
    webhook_url = Map.get(attrs, :webhook_url) || Map.get(attrs, "webhook_url")

    with {:ok, %{key_id: signing_key_id, public_key_x: x, public_key_y: y}} <-
           Key.generate_key("workspace_#{workspace_uuid}_signing"),
         {:ok, eoa_address, eoa_key_id} <- generate_eoa_keypair(workspace_uuid),
         {:ok, %{key_id: webhook_key_id, plaintext: webhook_secret}} <-
           HmacKeyStore.generate_hmac_key(),
         {:ok, %{key_id: status_index_key_id}} <- HmacKeyStore.generate_hmac_key() do
      changeset =
        Workspace.create_changeset(%{
          name: name,
          eoa_address: eoa_address,
          eoa_key_id: eoa_key_id,
          signing_key_id: signing_key_id,
          signing_public_key_x: x,
          signing_public_key_y: y,
          did: "did:sovra:#{eoa_address}",
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
      |> Ecto.Multi.run(:register_did, fn _repo, %{workspace: workspace} ->
        case register_did_on_chain(workspace, x, y) do
          :ok -> {:ok, :registered}
          {:error, :ethereum_not_configured} -> {:ok, :skipped}
          {:error, reason} -> {:error, reason}
        end
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{workspace: workspace}} ->
          {:ok, %{workspace: workspace, webhook_secret: webhook_secret}}

        {:error, :register_did, reason, _} ->
          {:error, {:chain_registration_failed, reason}}

        {:error, _step, changeset, _} ->
          {:error, changeset}
      end
    end
  end

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

  # ── Private helpers ────────────────────────────────────

  defp generate_eoa_keypair(workspace_uuid) do
    private_key = :crypto.strong_rand_bytes(32)

    case ExSecp256k1.create_public_key(private_key) do
      {:ok, public_key} ->
        <<4, pub_bytes::binary-64>> = public_key
        address_bytes = ExKeccak.hash_256(pub_bytes) |> binary_part(12, 20)
        eoa_address = "0x" <> Base.encode16(address_bytes, case: :lower)

        eoa_key_id = "workspace_#{workspace_uuid}_eoa"

        {:ok, eoa_address, eoa_key_id}

      {:error, _} = error ->
        error
    end
  end

  defp register_did_on_chain(workspace, pub_key_x, pub_key_y) do
    if ethereum_configured?() do
      service_endpoint = "#{ClaimUtils.base_url()}/#{workspace.did}"

      case DIDRegistry.register_issuer_did(
             workspace.eoa_address,
             pub_key_x,
             pub_key_y,
             service_endpoint
           ) do
        {:ok, _tx_hash} -> :ok
        {:error, _} = error -> error
      end
    else
      {:error, :ethereum_not_configured}
    end
  end

  defp ethereum_configured? do
    config = Application.get_env(:sovra, :ethereum, [])
    config[:admin_private_key] != nil and config[:did_registry_address] != nil
  end
end
