defmodule Sovra.Workspaces.ApiKeys do
  @moduledoc """
  Workspace API keys for server-to-server access to Sovra's issuance endpoints.
  Each workspace can have many labelled keys; plaintext is revealed exactly
  once at creation and never again. Revocation is soft (sets `revoked_at`)
  so historical `last_used_at` audits survive.
  """

  use Sovra.Log

  import Ecto.Query

  alias Sovra.Issuer.TokenHash
  alias Sovra.Repo
  alias Sovra.Workspaces.ApiKey

  @plaintext_prefix "sovra_sk_"

  @doc """
  Generate a new API key for the workspace. Returns the plaintext exactly once
  alongside the persisted `%ApiKey{}` record.
  """
  def create_api_key(workspace_id, name) do
    plaintext = generate_plaintext()
    hash = TokenHash.hash(plaintext)

    changeset =
      ApiKey.create_changeset(%{
        workspace_id: workspace_id,
        name: name,
        api_key_hash: hash
      })

    case Repo.insert(changeset) do
      {:ok, record} ->
        # An API key is a bearer credential for the whole workspace, so its
        # creation and revocation are the audit trail for who could issue
        # credentials and when. The actor comes from the request's log context.
        Log.event(:info, "API key created",
          event: "workspace.api_key.created",
          workspace_id: workspace_id,
          api_key_id: record.id,
          api_key_name: name
        )

        {:ok, %{api_key: plaintext, record: record}}

      {:error, _} = error ->
        error
    end
  end

  def list_api_keys(workspace_id) do
    from(k in ApiKey,
      where: k.workspace_id == ^workspace_id,
      order_by: [desc: k.inserted_at, desc: k.id]
    )
    |> Repo.all()
  end

  def get_api_key(workspace_id, id) do
    case Repo.get_by(ApiKey, id: id, workspace_id: workspace_id) do
      nil -> {:error, :not_found}
      key -> {:ok, key}
    end
  end

  def revoke_api_key(%ApiKey{} = record) do
    record
    |> ApiKey.revoke_changeset()
    |> Repo.update()
    |> tap(fn
      {:ok, _} ->
        Log.event(:info, "API key revoked",
          event: "workspace.api_key.revoked",
          workspace_id: record.workspace_id,
          api_key_id: record.id,
          api_key_name: record.name,
          last_used_at: record.last_used_at
        )

      {:error, _} ->
        :ok
    end)
  end

  @doc """
  Resolve a plaintext API key to its active record + workspace.
  Returns `{:error, :invalid}` for unknown, malformed, or revoked keys.
  """
  def find_active_by_plaintext(plaintext) when is_binary(plaintext) do
    hash = TokenHash.hash(plaintext)

    query =
      from(k in ApiKey,
        where: k.api_key_hash == ^hash and is_nil(k.revoked_at),
        preload: :workspace
      )

    case Repo.one(query) do
      nil -> {:error, :invalid}
      %ApiKey{} = key -> {:ok, key}
    end
  end

  def find_active_by_plaintext(_), do: {:error, :invalid}

  @doc """
  Fire-and-forget update of `last_used_at`. Called from the auth plug so we
  don't want to block or crash the request if this fails. In test mode this
  runs synchronously to play nicely with the SQL sandbox.
  """
  def touch_last_used(api_key_id) do
    if Application.get_env(:sovra, :env) == :test do
      touch_now(api_key_id)
    else
      Task.Supervisor.start_child(Sovra.TaskSupervisor, fn -> touch_now(api_key_id) end)
    end

    :ok
  end

  defp touch_now(api_key_id) do
    case Repo.get(ApiKey, api_key_id) do
      nil -> :ok
      %ApiKey{} = record -> record |> ApiKey.touch_used_changeset() |> Repo.update()
    end
  end

  defp generate_plaintext do
    random = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    @plaintext_prefix <> random
  end
end
