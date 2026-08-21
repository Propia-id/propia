defmodule Sovra.Repo.Migrations.CreateIssuerInvitations do
  @moduledoc """
  Invitations to the issuer console. Two secrets per row, stored only as
  SHA-256: `token_hash` backs the emailed link, and `code_hash` a short code
  sent to the invited address when the form is submitted, so that a forwarded
  link is not enough to claim the account.
  """
  use Ecto.Migration

  def change do
    create table(:issuer_invitations, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :email, :citext, null: false
      add :token_hash, :string, null: false

      # Audit: who authorized this. Nullable so removing an admin keeps the
      # trail instead of deleting it.
      add :invited_by_user_id, references(:users, type: :binary_id, on_delete: :nilify_all)

      add :expires_at, :utc_datetime, null: false
      add :used_at, :utc_datetime
      add :revoked_at, :utc_datetime

      # Set on request_code/1, not at creation.
      add :code_hash, :string
      add :code_expires_at, :utc_datetime
      add :code_attempts, :integer, null: false, default: 0

      timestamps(type: :utc_datetime)
    end

    create unique_index(:issuer_invitations, [:token_hash])
    create index(:issuer_invitations, [:email])
  end
end
