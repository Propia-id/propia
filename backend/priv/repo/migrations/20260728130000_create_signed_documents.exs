defmodule Sovra.Repo.Migrations.CreateSignedDocuments do
  use Ecto.Migration

  def change do
    create table(:signed_documents, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :restrict),
        null: false

      add :schema_id, references(:credential_schemas, type: :binary_id, on_delete: :restrict),
        null: false

      # The signed JWS is the source of truth: verification needs the exact bytes
      # that were signed, and re-serializing `claims` would not reproduce them.
      add :credential, :text, null: false

      # Decoded claim values — a view for listing and rendering only.
      add :claims, :map, null: false, default: %{}

      # sha256 of the JWS signing input. This is what the signature covers, and
      # the key the signature is stored under on-chain.
      add :digest, :binary, null: false

      # `signed` is the state between insert and anchoring, so a row only stays
      # there if the process died in between.
      add :status, :string, null: false, default: "signed"

      # Allocated when revocation lands; the on-chain bitmap index.
      add :status_list_index, :integer

      add :tx_hash, :string
      add :signed_at, :utc_datetime, null: false
      add :anchored_at, :utc_datetime
      add :revoked_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:signed_documents, [:workspace_id])
    create unique_index(:signed_documents, [:workspace_id, :digest])

    create constraint(:signed_documents, :signed_documents_status_check,
             check: "status IN ('signed', 'anchored', 'failed', 'revoked')"
           )
  end
end
