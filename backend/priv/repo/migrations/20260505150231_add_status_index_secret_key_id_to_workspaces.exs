defmodule Sovra.Repo.Migrations.AddStatusIndexSecretKeyIdToWorkspaces do
  use Ecto.Migration

  import Ecto.Query, only: [from: 2]

  alias Sovra.Crypto.HmacKeyStore
  alias Sovra.Repo

  def up do
    alter table(:workspaces) do
      add :status_index_secret_key_id, :string
    end

    flush()

    workspace_ids =
      from(w in "workspaces",
        where: is_nil(w.status_index_secret_key_id),
        select: w.id
      )
      |> Repo.all()

    Enum.each(workspace_ids, fn id ->
      {:ok, %{key_id: key_id}} = HmacKeyStore.generate_hmac_key()

      from(w in "workspaces", where: w.id == ^id)
      |> Repo.update_all(set: [status_index_secret_key_id: key_id])
    end)

    alter table(:workspaces) do
      modify :status_index_secret_key_id, :string, null: false
    end
  end

  def down do
    alter table(:workspaces) do
      remove :status_index_secret_key_id
    end
  end
end
