defmodule Sovra.Repo.Migrations.UniqueMdlSigningKey do
  use Ecto.Migration

  # A credential carrying an ISO docType names no issuer — the `x5chain` leaf
  # does, by naming the key that signed it. Resolution is therefore a lookup
  # from public key to workspace, and that only answers a question if the key
  # belongs to exactly one.
  #
  # KMS will not hand out the same key twice, so this index never fires. It is
  # here because `Sovra.Mdoc.IssuerTrust.resolve/2` depends on the invariant,
  # and an invariant the code relies on belongs in the schema rather than in a
  # comment about how unlikely the alternative is.
  def change do
    create unique_index(
             :workspaces,
             [:mdl_signing_public_key_x, :mdl_signing_public_key_y],
             where: "mdl_signing_key_id IS NOT NULL",
             name: :workspaces_mdl_signing_key_unique
           )
  end
end
