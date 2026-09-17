defmodule Sovra.Repo.Migrations.AllowMixedCaseDocTypes do
  use Ecto.Migration

  # The original constraint accepted only lowercase, which rejects
  # `org.iso.18013.5.1.mDL` — the one document type the whole mDL feature
  # exists to issue, and the example the validation error itself gives.
  #
  # A docType looks like a hostname but is not one: nothing resolves it, and no
  # reader lowercases it before comparing. `mdl` and `mDL` are two different
  # document types, so the rule has to be case-sensitive and has to allow both.
  @lowercase_only "^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$"
  @any_case "^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)+$"

  def up do
    drop constraint(:credential_schemas, :credential_schemas_doc_type_shape_check)

    create constraint(:credential_schemas, :credential_schemas_doc_type_shape_check,
             check: "doc_type IS NULL OR doc_type ~ '#{@any_case}'"
           )
  end

  def down do
    drop constraint(:credential_schemas, :credential_schemas_doc_type_shape_check)

    create constraint(:credential_schemas, :credential_schemas_doc_type_shape_check,
             check: "doc_type IS NULL OR doc_type ~ '#{@lowercase_only}'"
           )
  end
end
