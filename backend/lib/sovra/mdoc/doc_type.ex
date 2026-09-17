defmodule Sovra.Mdoc.DocType do
  @moduledoc """
  docType and namespace generation for mdoc schemas.

  Generated unless the schema names its own:

      io.sovra.<workspace-eth-address>.<schema_id>.1

  and the namespace is then the docType. Deriving it rather than accepting it
  as input buys three things: uniqueness without a constraint, an issuer
  address a verifier can read back out, and stability — a workspace rename
  cannot touch it, because the address never changes.

  The trade is readability. That is acceptable because a docType is machine
  facing: an operator only ever sees it rendered read-only in the schema
  builder.

  ## An operator-supplied docType carries no issuer address

  A schema may name its own — `org.iso.18013.5.1.mDL` — and then this module
  has no address to embed and `issuer_address/1` returns `:error`. That is not
  a failure: such a credential is meant to be trusted through its certificate
  chain instead, which is why `Sovra.Mdl.can_issue_iso_doc_types?/1` requires a
  document signer before a schema may name one. `Sovra.Mdoc.IssuerTrust` is
  where the two routes meet.

  ## docType and namespace are different strings

  ISO pairs docType `org.iso.18013.5.1.mDL` with namespace
  `org.iso.18013.5.1` — the document type is not where the data elements live.
  Sovra's generated schemas use one string for both, which is why the
  distinction was invisible until now; `namespace/2` is the seam.

  ## This string is a wire contract

  The docType is signed into the MSO and named in every DCQL query, so the
  wallet, the verifier and this module must agree on it byte for byte —
  including the `0x` prefix and the lowercasing. Changing the template orphans
  every credential already issued under the old one, so treat it the way you
  would a database primary key.
  """

  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Workspaces.Workspace

  @prefix "io.sovra"
  @version "1"

  @doc """
  The docType for a schema, or `nil` when there isn't one.

  Returns `nil` for `vc+sd-jwt` schemas (they have no docType) and for a
  workspace whose `eoa_address` is still unset — provisioning is asynchronous,
  and `list_schemas/1` does not assert it has finished, so this has to render
  rather than raise.
  """
  @spec build(Workspace.t(), CredentialSchema.t()) :: String.t() | nil
  def build(%Workspace{}, %CredentialSchema{format: "mso_mdoc", doc_type: doc_type})
      when is_binary(doc_type) and doc_type != "",
      do: doc_type

  def build(%Workspace{} = workspace, %CredentialSchema{format: "mso_mdoc"} = schema) do
    case issuer_prefix(workspace) do
      nil -> nil
      prefix -> "#{prefix}#{schema.schema_id}.#{@version}"
    end
  end

  def build(_workspace, _schema), do: nil

  @doc """
  The namespace this schema's data elements live in.

  Defaults to the docType, which is what every generated schema means and what
  every credential issued so far carries. A schema that names its own is
  usually an ISO one, where the two differ by design.
  """
  @spec namespace(Workspace.t(), CredentialSchema.t()) :: String.t() | nil
  def namespace(%Workspace{}, %CredentialSchema{namespace: namespace})
      when is_binary(namespace) and namespace != "",
      do: namespace

  def namespace(%Workspace{} = workspace, %CredentialSchema{} = schema),
    do: build(workspace, schema)

  @doc "The `io.sovra.<address>.` prefix every docType this workspace issues shares."
  @spec issuer_prefix(Workspace.t()) :: String.t() | nil
  def issuer_prefix(%Workspace{eoa_address: nil}), do: nil
  def issuer_prefix(%Workspace{eoa_address: ""}), do: nil

  def issuer_prefix(%Workspace{eoa_address: address}),
    do: "#{@prefix}.#{String.downcase(address)}."

  @doc """
  The issuer address embedded in `doc_type`.

  This is how a verifier learns who issued a credential: the docType is inside
  the signed MSO, so the answer comes from the issuer's own signed content
  rather than from an unsigned header a holder could rewrite.

  Positional rather than a scan for anything address-shaped. The address is
  always the segment following the `#{@prefix}.` prefix, and `schema_id` is
  operator-chosen — a schema called `0xdeadbeef` must not be mistaken for one.

  Only the lowercase, full-length form `build/2` emits is accepted. The docType
  is a wire contract, so a string this module would never have generated is not
  one to resolve an issuer from.

  The length matters as much as the alphabet, because this predicate is also
  what decides the *route*: `Sovra.Mdoc.IssuerTrust` reads an address here as
  "trust this through the registry", and its absence as "trust this through the
  certificate chain". `verification-sdk`'s `isGeneratedDocType` requires forty
  hex digits, so accepting `io.sovra.0xab.schema.1` here would send the two
  verifiers down different routes for one credential — which is the one thing
  the two-route design may not allow.

  Returns `:error` for an operator-supplied docType, which embeds no address by
  construction. The caller's next move is the certificate chain, not a failure.
  """
  @spec issuer_address(String.t()) :: {:ok, String.t()} | :error
  def issuer_address(doc_type) when is_binary(doc_type) do
    with @prefix <> "." <> rest <- doc_type,
         # At least one segment has to follow the address, or the docType is a
         # bare issuer prefix naming no schema.
         [address | [_ | _]] <- String.split(rest, "."),
         "0x" <> hex <- address,
         true <- String.match?(hex, ~r/^[0-9a-f]{40}$/) do
      {:ok, address}
    else
      _ -> :error
    end
  end

  def issuer_address(_doc_type), do: :error
end
