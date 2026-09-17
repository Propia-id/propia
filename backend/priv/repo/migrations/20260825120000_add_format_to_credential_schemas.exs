defmodule Sovra.Repo.Migrations.AddFormatToCredentialSchemas do
  use Ecto.Migration

  # An mdoc schema is issued as ISO 18013-5 CBOR rather than as an SD-JWT. The
  # wire format is fixed at creation and not per revision: the docType is
  # derived from the schema and baked into every credential already sitting in a
  # holder's wallet, so a revision that flipped the format would orphan them.
  #
  # mdoc is also credential-only. A document schema is signed straight to a PDF
  # with no wallet and no holder key, which an mdoc has no way to express — the
  # second constraint makes that combination unrepresentable rather than merely
  # discouraged.
  def change do
    alter table(:credential_schemas) do
      add :format, :string, null: false, default: "vc+sd-jwt"
    end

    create constraint(:credential_schemas, :credential_schemas_format_check,
             check: "format IN ('vc+sd-jwt', 'mso_mdoc')"
           )

    create constraint(:credential_schemas, :credential_schemas_mdoc_kind_check,
             check: "format = 'vc+sd-jwt' OR kind = 'credential'"
           )
  end
end
