defmodule Sovra.Workspaces do
  @moduledoc """
  Workspace lifecycle — per-tenant operational units that act as credential
  issuers. Each workspace owns its DID, signing keys, and on-chain EOA.

  Workspaces always belong to an organization.
  """

  import Ecto.Query

  alias Sovra.Crypto.Key
  alias Sovra.Ethereum.DIDRegistry
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Repo
  alias Sovra.Workspaces.Workspace

  require Logger

  def create_workspace(name, organization_id) do
    workspace_uuid = Ecto.UUID.generate()

    with {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} <-
           Key.generate_key("workspace_#{workspace_uuid}_signing"),
         {:ok, eoa_address, eoa_key_id} <- generate_eoa_keypair(workspace_uuid) do
      changeset =
        Workspace.create_changeset(%{
          name: name,
          eoa_address: eoa_address,
          eoa_key_id: eoa_key_id,
          signing_key_id: key_id,
          signing_public_key_x: x,
          signing_public_key_y: y,
          did: "did:sovra:#{eoa_address}",
          organization_id: organization_id
        })

      Ecto.Multi.new()
      |> Ecto.Multi.insert(:workspace, changeset)
      |> Ecto.Multi.run(:register_did, fn _repo, %{workspace: workspace} ->
        case register_did_on_chain(workspace.eoa_address, x, y) do
          :ok -> {:ok, :registered}
          {:error, :ethereum_not_configured} -> {:ok, :skipped}
          {:error, reason} -> {:error, reason}
        end
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{workspace: workspace}} -> {:ok, workspace}
        {:error, :register_did, reason, _} -> {:error, {:chain_registration_failed, reason}}
        {:error, :workspace, changeset, _} -> {:error, changeset}
      end
    end
  end

  def get_workspace(id) do
    case Repo.get(Workspace, id) do
      nil -> {:error, :workspace_not_found}
      workspace -> {:ok, workspace}
    end
  end

  def list_workspaces do
    from(w in Workspace,
      left_join: a in Sovra.Issuer.IssuerAccount,
      on: a.workspace_id == w.id,
      order_by: [desc: w.inserted_at],
      select: %{id: w.id, name: w.name, did: w.did, status: w.status, email: a.email}
    )
    |> Repo.all()
  end

  def list_workspaces_for_organization(organization_id) do
    from(w in Workspace,
      where: w.organization_id == ^organization_id,
      order_by: [asc: w.name]
    )
    |> Repo.all()
  end

  def get_first_workspace do
    case Repo.one(from(w in Workspace, where: w.status == "active", limit: 1)) do
      nil -> {:error, :no_workspaces}
      workspace -> {:ok, workspace}
    end
  end

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

  defp register_did_on_chain(eoa_address, pub_key_x, pub_key_y) do
    if ethereum_configured?() do
      service_endpoint = ClaimUtils.base_url()

      case DIDRegistry.register_issuer_did(eoa_address, pub_key_x, pub_key_y, service_endpoint) do
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
