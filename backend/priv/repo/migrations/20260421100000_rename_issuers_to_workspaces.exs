defmodule Sovra.Repo.Migrations.RenameIssuersToWorkspaces do
  use Ecto.Migration

  def up do
    rename table(:issuers), to: table(:workspaces)
    rename table(:issuer_accounts), :issuer_id, to: :workspace_id

    execute "ALTER INDEX issuers_pkey RENAME TO workspaces_pkey"
    execute "ALTER INDEX issuers_eoa_address_index RENAME TO workspaces_eoa_address_index"
    execute "ALTER INDEX issuers_did_index RENAME TO workspaces_did_index"

    execute "ALTER INDEX issuer_accounts_issuer_id_index RENAME TO issuer_accounts_workspace_id_index"
  end

  def down do
    execute "ALTER INDEX issuer_accounts_workspace_id_index RENAME TO issuer_accounts_issuer_id_index"
    execute "ALTER INDEX workspaces_did_index RENAME TO issuers_did_index"
    execute "ALTER INDEX workspaces_eoa_address_index RENAME TO issuers_eoa_address_index"
    execute "ALTER INDEX workspaces_pkey RENAME TO issuers_pkey"

    rename table(:issuer_accounts), :workspace_id, to: :issuer_id
    rename table(:workspaces), to: table(:issuers)
  end
end
