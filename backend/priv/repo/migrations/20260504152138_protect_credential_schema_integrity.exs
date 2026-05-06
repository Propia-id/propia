defmodule Sovra.Repo.Migrations.ProtectCredentialSchemaIntegrity do
  use Ecto.Migration

  def change do
    drop unique_index(:credential_schemas, [:issuer_id, :schema_id])
    create unique_index(:credential_schemas, [:issuer_id, :schema_id, :version])

    alter table(:issued_credentials) do
      modify :schema_id,
             references(:credential_schemas, type: :binary_id, on_delete: :restrict),
             from: references(:credential_schemas, type: :binary_id)
    end

    alter table(:credential_offers) do
      modify :schema_id,
             references(:credential_schemas, type: :binary_id, on_delete: :restrict),
             from: references(:credential_schemas, type: :binary_id)
    end
  end
end
