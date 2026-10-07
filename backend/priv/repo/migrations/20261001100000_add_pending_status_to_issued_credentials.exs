defmodule Sovra.Repo.Migrations.AddPendingStatusToIssuedCredentials do
  use Ecto.Migration

  def change do
    # `status` stays what the chain confirms. `pending_status` is the target of a
    # change whose transaction is on the way (`Sovra.Issuer.CredentialStatusJob`),
    # and `status_change_error` says why the last one did not land.
    alter table(:issued_credentials) do
      add :pending_status, :string
      add :status_change_error, :text
    end

    create constraint(:issued_credentials, :issued_credentials_pending_status_check,
             check:
               "pending_status IS NULL OR pending_status IN ('issued', 'revoked', 'suspended')"
           )
  end
end
