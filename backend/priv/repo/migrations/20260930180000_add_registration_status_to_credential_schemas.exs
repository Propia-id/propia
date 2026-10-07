defmodule Sovra.Repo.Migrations.AddRegistrationStatusToCredentialSchemas do
  use Ecto.Migration

  def change do
    # Existing schemas had their type registered inside the create request, so
    # they start `registered`. The default then flips to `pending` for new
    # ones, which wait for `Sovra.Issuer.CredentialTypeRegistrationJob`.
    alter table(:credential_schemas) do
      add :registration_status, :string, null: false, default: "registered"
      add :registration_error, :text
    end

    alter table(:credential_schemas) do
      modify :registration_status, :string,
        null: false,
        default: "pending",
        from: {:string, null: false, default: "registered"}
    end

    create constraint(:credential_schemas, :credential_schemas_registration_status_check,
             check: "registration_status IN ('pending', 'registered', 'failed')"
           )
  end
end
