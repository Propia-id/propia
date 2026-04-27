defmodule Sovra.Repo.Migrations.RemoveWorkspaceIdFromIssuerAccounts do
  use Ecto.Migration

  def up do
    drop_if_exists unique_index(:issuer_accounts, [:workspace_id],
                     name: :issuer_accounts_workspace_id_index
                   )

    alter table(:issuer_accounts) do
      remove :workspace_id
    end
  end

  def down do
    alter table(:issuer_accounts) do
      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all)
    end

    create unique_index(:issuer_accounts, [:workspace_id])
  end
end
