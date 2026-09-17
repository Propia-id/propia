defmodule Sovra.Mdoc.MetaNamespace do
  @moduledoc """
  The Sovra-reserved namespace every issued mdoc carries alongside its docType
  namespace.

  ISO gives an mdoc nowhere to put several things Sovra's model needs, so they
  ride here as ordinary data elements — issuer-signed like any other, and
  therefore tamper-evident:

    * `holder_did` — an mdoc identifies its holder only by
      `MSO.deviceKeyInfo.deviceKey`, a raw COSE key with no DID anywhere. But
      `Sovra.Verification.Session` requires a `holder_did` to complete, and
      more importantly our security model resolves the holder's *currently
      authorized* keys on-chain rather than trusting whatever key a credential
      was born with. Without the DID there is nothing to resolve, and a
      rotated-away passkey would keep working forever.

    * `status_list_index` — mdoc has no `credentialStatus` field, so the index
      into the issuer's revocation bitmap has to travel with the credential.

    * `issuer_address` — the workspace EOA the revocation bitmaps and the
      Issuer Trust Registry are keyed by. A generated docType embeds it, which
      is why this element did not exist until ISO docTypes did: an ISO docType
      carries no address, and a chain-only verifier has no database to look one
      up in. The certificate names the *key*, not the address.

      Carried on both routes rather than only the certificate one, so there is
      one place to read it from.

      Being issuer-signed makes it tamper-evident in transit and nothing more:
      the issuer chose it. On the generated route a wrong value cannot get far,
      because the docType carries the address that selected the verifying key.
      On the certificate route nothing in the chain names a workspace, so
      `Sovra.Verification.Verifier.check_issuer_address/3` requires this element
      to match the workspace the `x5chain` leaf resolved to — without it, any
      workspace holding a document signer could issue credentials attributed to
      another, against a revocation bitmap and a registry entry that are not its
      own.

    * `namespace` — where this credential's data elements live. ISO pairs
      docType `org.iso.18013.5.1.mDL` with namespace `org.iso.18013.5.1`, so a
      reader cannot derive one from the other, and a document may carry several
      namespaces besides. Naming it is what lets the wallet render a claim
      unqualified instead of as `org.iso.18013.5.1.family_name`.

    * `mandatory_elements` — the `disclosable: false` set, frozen at issuance,
      keyed by namespace. Freezing it is the point: a verifier needs no schema
      lookup, and a later schema revision cannot retroactively change what an
      already-issued credential is required to disclose. Keyed by namespace
      because element identifiers are only unique within one, so a flat list
      could not say which `document_number` it meant.

    * `credential_type` — what the issuer registered on-chain in the Issuer
      Trust Registry. The docType is derived from the schema and is not what
      the registry is keyed by, so a chain-only verifier — which has no
      database to look a workspace up in — would otherwise have no way to ask
      whether this issuer is authorized for this type of credential.

  ## Why the verifier must require all of them

  These are enforcement inputs supplied by the party being enforced against. A
  holder who could omit `mandatory_elements` would escape the mandatory-element
  check; one who could omit `status_list_index` would escape revocation. So the
  verifier treats a missing or incomplete meta namespace as a hard failure
  rather than as absent metadata — which is safe precisely because the whole
  namespace is covered by the issuer's signature.

  Rejected alternative: reserved element ids inside the docType namespace.
  They would collide with operator-chosen claim keys.
  """

  @namespace "io.sovra.meta.1"

  @holder_did "holder_did"
  @status_list_index "status_list_index"
  @mandatory_elements "mandatory_elements"
  @credential_type "credential_type"
  @namespace_element "namespace"
  @issuer_address "issuer_address"

  @elements [
    @holder_did,
    @status_list_index,
    @mandatory_elements,
    @credential_type,
    @namespace_element,
    @issuer_address
  ]

  @doc "The reserved namespace identifier."
  def namespace, do: @namespace

  @doc "Every element identifier this namespace defines."
  def elements, do: @elements

  @doc """
  The element map for an issued credential.

  `mandatory_elements` maps each namespace to the element identifiers within it
  that the holder may not withhold.
  """
  @spec build(
          String.t(),
          non_neg_integer(),
          %{String.t() => [String.t()]},
          String.t(),
          String.t(),
          String.t()
        ) :: %{String.t() => term()}
  def build(
        holder_did,
        status_list_index,
        mandatory_elements,
        credential_type,
        namespace,
        issuer_address
      )
      when is_binary(holder_did) and is_integer(status_list_index) and
             is_map(mandatory_elements) and is_binary(credential_type) and
             is_binary(namespace) and is_binary(issuer_address) do
    %{
      @holder_did => holder_did,
      @status_list_index => status_list_index,
      @mandatory_elements => mandatory_elements,
      @credential_type => credential_type,
      @namespace_element => namespace,
      @issuer_address => String.downcase(issuer_address)
    }
  end

  @doc """
  Pull the meta elements out of a presented namespace map.

  Fails unless all of them are present and well-typed — see the moduledoc for
  why absence cannot be tolerated.
  """
  @spec extract(%{String.t() => %{String.t() => term()}}) ::
          {:ok,
           %{
             holder_did: String.t(),
             status_list_index: non_neg_integer(),
             mandatory_elements: %{String.t() => [String.t()]},
             credential_type: String.t(),
             namespace: String.t(),
             issuer_address: String.t()
           }}
          | {:error, :missing_meta_namespace | :malformed_meta_namespace}
  def extract(namespaces) when is_map(namespaces) do
    case Map.get(namespaces, @namespace) do
      nil ->
        {:error, :missing_meta_namespace}

      elements when is_map(elements) ->
        with %{
               @holder_did => did,
               @status_list_index => index,
               @mandatory_elements => mandatory,
               @credential_type => credential_type,
               @namespace_element => namespace,
               @issuer_address => issuer_address
             } <- elements,
             true <- is_binary(did) and did != "",
             true <- is_integer(index) and index >= 0,
             true <- valid_mandatory?(mandatory),
             true <- is_binary(credential_type) and credential_type != "",
             true <- is_binary(namespace) and namespace != "",
             true <- valid_address?(issuer_address) do
          {:ok,
           %{
             holder_did: did,
             status_list_index: index,
             mandatory_elements: mandatory,
             credential_type: credential_type,
             namespace: namespace,
             issuer_address: issuer_address
           }}
        else
          _ -> {:error, :malformed_meta_namespace}
        end

      _ ->
        {:error, :malformed_meta_namespace}
    end
  end

  def extract(_), do: {:error, :missing_meta_namespace}

  defp valid_mandatory?(mandatory) when is_map(mandatory) do
    Enum.all?(mandatory, fn {namespace, elements} ->
      is_binary(namespace) and is_list(elements) and Enum.all?(elements, &is_binary/1)
    end)
  end

  defp valid_mandatory?(_), do: false

  # Lowercase only, the single form `build/6` writes and the same form
  # `Sovra.Mdoc.DocType` embeds in a generated docType. Accepting a checksummed
  # spelling as well would make two credentials disagree about whether they came
  # from the same issuer.
  defp valid_address?(address) when is_binary(address),
    do: String.match?(address, ~r/^0x[0-9a-f]{40}$/)

  defp valid_address?(_), do: false
end
