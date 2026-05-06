defmodule Sovra.Repo.Migrations.RenameIssuerAccountsToUsers do
  @moduledoc """
  The schema layer was renamed from `Sovra.Issuer.IssuerAccount` to
  `Sovra.Accounts.User` earlier in this branch — the table itself was
  left as `issuer_accounts` to keep the diff small. This migration
  finishes the job: the table now matches the module.

  PostgreSQL preserves foreign-key constraints across `RENAME TABLE`
  (FKs reference table OIDs, not names), so the references from
  `organization_members`, `workspace_members`, `refresh_tokens`, and
  `password_reset_tokens` continue to work without any further changes.
  Index names are renamed for cleanliness.
  """
  use Ecto.Migration

  def up do
    rename table(:issuer_accounts), to: table(:users)

    execute "ALTER INDEX issuer_accounts_pkey RENAME TO users_pkey"
    execute "ALTER INDEX issuer_accounts_email_index RENAME TO users_email_index"
  end

  def down do
    execute "ALTER INDEX users_email_index RENAME TO issuer_accounts_email_index"
    execute "ALTER INDEX users_pkey RENAME TO issuer_accounts_pkey"

    rename table(:users), to: table(:issuer_accounts)
  end
end
