defmodule Sovra.Repo.Migrations.CreateRefreshTokens do
  use Ecto.Migration

  def change do
    create table(:refresh_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :user_id, references(:issuer_accounts, type: :binary_id, on_delete: :delete_all),
        null: false

      add :token_hash, :string, null: false
      add :expires_at, :utc_datetime, null: false
      add :revoked_at, :utc_datetime
      add :last_used_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:refresh_tokens, [:token_hash])
    # Partial index supports `revoke_all_for_user/1` (WHERE user_id = ?
    # AND revoked_at IS NULL). Only active tokens are indexed, which keeps
    # the index small as expired/revoked rows accumulate.
    create index(:refresh_tokens, [:user_id], where: "revoked_at IS NULL")
  end
end
