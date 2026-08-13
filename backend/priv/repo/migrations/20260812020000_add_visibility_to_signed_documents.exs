defmodule Sovra.Repo.Migrations.AddVisibilityToSignedDocuments do
  use Ecto.Migration

  # Whether holding the link is enough to read the document. `public` is the
  # capability model the id already implies; `private` also requires a session,
  # for documents whose contents should not be readable by whoever a link
  # reaches. It gates our endpoints, not the credential once it has been handed
  # out: anyone holding the JWS can still verify it against the chain.
  #
  # Private by default, so publishing is a choice rather than an oversight.
  def change do
    alter table(:signed_documents) do
      add :visibility, :string, null: false, default: "private"
    end

    create constraint(:signed_documents, :signed_documents_visibility_check,
             check: "visibility IN ('public', 'private')"
           )
  end
end
