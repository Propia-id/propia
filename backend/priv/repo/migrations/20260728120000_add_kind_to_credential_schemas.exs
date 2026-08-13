defmodule Sovra.Repo.Migrations.AddKindToCredentialSchemas do
  use Ecto.Migration

  # A "document" schema is issued directly by the issuer — no wallet, no holder
  # binding. Everything else about it (claims, versioning, on-chain type
  # registration) is identical to a credential schema.
  def change do
    alter table(:credential_schemas) do
      add :kind, :string, null: false, default: "credential"
    end

    create constraint(:credential_schemas, :credential_schemas_kind_check,
             check: "kind IN ('credential', 'document')"
           )
  end
end
