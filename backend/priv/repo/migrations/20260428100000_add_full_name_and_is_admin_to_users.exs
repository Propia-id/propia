defmodule Sovra.Repo.Migrations.AddFullNameAndIsAdminToUsers do
  use Ecto.Migration

  def up do
    alter table(:issuer_accounts) do
      add :is_admin, :boolean, null: false, default: false
      add :full_name, :string
    end

    execute "UPDATE issuer_accounts SET is_admin = true WHERE role = 'admin'"

    execute "UPDATE issuer_accounts SET full_name = split_part(email, '@', 1) WHERE full_name IS NULL"

    alter table(:issuer_accounts) do
      modify :full_name, :string, null: false
      remove :role
    end
  end

  def down do
    alter table(:issuer_accounts) do
      add :role, :string, null: false, default: "issuer"
    end

    execute "UPDATE issuer_accounts SET role = 'admin' WHERE is_admin = true"

    alter table(:issuer_accounts) do
      remove :full_name
      remove :is_admin
    end
  end
end
