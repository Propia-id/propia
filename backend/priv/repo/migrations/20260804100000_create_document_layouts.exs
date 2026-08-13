defmodule Sovra.Repo.Migrations.CreateDocumentLayouts do
  use Ecto.Migration

  # The page layout of a document schema: absolutely positioned elements, some of
  # them bound to a claim. Presentation only, not covered by the signature.
  #
  # Its own table rather than a column on credential_schemas, which credential
  # schemas share: a credential has no page, so the column would always be null
  # for them. Same reason credential designs live apart.
  def change do
    create table(:document_layouts, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :credential_schema_id,
          references(:credential_schemas, type: :binary_id, on_delete: :delete_all),
          null: false

      add :layout, :map, null: false

      # Bumped on every edit.
      add :version, :integer, null: false, default: 1

      timestamps(type: :utc_datetime)
    end

    # One layout per schema version. A schema revision is a new row in
    # credential_schemas, so it gets its own layout.
    create unique_index(:document_layouts, [:credential_schema_id])
  end
end
