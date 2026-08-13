defmodule Sovra.Repo.Migrations.DropClaimsFromSignedDocuments do
  use Ecto.Migration

  # The decoded copy the page and the API used to render from. Both read the
  # credential now, so the column had no readers left, and a second copy of the
  # claims is a second thing that can disagree with the signature.
  def change do
    alter table(:signed_documents) do
      remove :claims, :map, null: false, default: %{}
    end
  end
end
