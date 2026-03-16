defmodule Sovra.Repo.Migrations.AddRoleToIssuerAccounts do
  use Ecto.Migration

  def up do
    alter table(:issuer_accounts) do
      add :role, :string, null: false, default: "issuer"

      modify :issuer_id, references(:issuers, type: :binary_id, on_delete: :delete_all),
        null: true,
        from: references(:issuers, type: :binary_id, on_delete: :delete_all)
    end
  end

  def down do
    # Remove admin accounts (no issuer_id) before making column non-null again
    execute "DELETE FROM issuer_accounts WHERE issuer_id IS NULL"

    alter table(:issuer_accounts) do
      remove :role

      modify :issuer_id, references(:issuers, type: :binary_id, on_delete: :delete_all),
        null: false,
        from: references(:issuers, type: :binary_id, on_delete: :delete_all)
    end
  end
end
