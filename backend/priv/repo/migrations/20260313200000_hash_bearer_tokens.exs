defmodule Sovra.Repo.Migrations.HashBearerTokens do
  use Ecto.Migration

  def up do
    # Rename plaintext token columns to _hash variants
    rename table(:credential_offers), :pre_authorized_code, to: :pre_authorized_code_hash
    rename table(:credential_offers), :access_token, to: :access_token_hash

    # Allow nullable (cleared after credential delivery)
    alter table(:credential_offers) do
      modify :pre_authorized_code_hash, :string, null: true
      modify :sd_jwt, :text, null: true
    end

    # Drop old indexes and create new ones on hash columns
    drop_if_exists unique_index(:credential_offers, [:pre_authorized_code])
    drop_if_exists unique_index(:credential_offers, [:access_token])

    create unique_index(:credential_offers, [:pre_authorized_code_hash])
    create unique_index(:credential_offers, [:access_token_hash])
  end

  def down do
    drop_if_exists unique_index(:credential_offers, [:pre_authorized_code_hash])
    drop_if_exists unique_index(:credential_offers, [:access_token_hash])

    rename table(:credential_offers), :pre_authorized_code_hash, to: :pre_authorized_code
    rename table(:credential_offers), :access_token_hash, to: :access_token

    alter table(:credential_offers) do
      modify :pre_authorized_code, :string, null: false
      modify :sd_jwt, :text, null: false
    end

    create unique_index(:credential_offers, [:pre_authorized_code])
    create unique_index(:credential_offers, [:access_token])
  end
end
