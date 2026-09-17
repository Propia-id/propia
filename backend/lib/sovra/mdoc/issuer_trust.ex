defmodule Sovra.Mdoc.IssuerTrust do
  @moduledoc """
  How a verifier finds the issuer of an mdoc — **seam 1** of the retrofit
  contract.

  There are two routes, and the credential's own docType says which one
  applies:

    * a **generated** docType (`io.sovra.<address>.<schema>.1`) embeds the
      issuing workspace's address, so the answer is a lookup on a string the
      MSO signs;
    * an **ISO** docType (`org.iso.18013.5.1.mDL`) embeds nothing, and the
      answer comes from the `x5chain` in `IssuerAuth` — the certificate names
      the key, and we hold the key.

  Issuance reads the same signal through `issuer_auth_material/2`, so the two
  sides cannot pick different routes for the same credential: whichever way
  `Sovra.Mdoc.DocType.issuer_address/1` answers at issuance is the way it
  answers at verification.

  ## Why the chain is trustworthy in an unprotected header

  ISO 18013-5 puts `x5chain` in the *unprotected* header, which the COSE
  signature does not cover, and that is fine — because the chain is not what
  makes the credential trustworthy. It only says which key to try. Substituting
  a different chain substitutes a different key, and then the signature does
  not verify. An attacker who could produce a chain *and* a matching signature
  would already hold a document signer key of ours.

  So the order matters: resolve the key from the chain, then verify the
  signature against it. Never the reverse, and never "the chain validated, so
  the credential is good".

  ## What re-validating the chain at verification time buys

  `Sovra.Mdl.register_document_signer/3` already checked this certificate
  against the Annex B profile and its admitted root. Checking again here is not
  redundant: a Document Signer Certificate is capped at 457 days, so the
  interesting failure is one that did not exist at registration — the
  certificate has since expired. A reader that only checked at registration
  would keep accepting credentials from a signer the rest of the world has
  stopped accepting.

  ## The DID hint is a hint, and nothing reads it

  On the generated-docType route `unprotected_header/1` still writes a
  `did:sovra` reference into `IssuerAuth`, so a reader that knows the label can
  skip parsing a docType. No verification path consults it.

  That is deliberate. COSE does not cover the unprotected header, so anything
  there can be stripped or rewritten in transit, and a verifier that *needed*
  it would reject perfectly valid credentials whenever it went missing. It also
  adds nothing: a workspace DID is `"did:sovra:" <> eoa_address`
  (`Sovra.Workspaces.WorkspaceProvisioningJob`), which is the same address the
  docType already carries — signed. The header is a weaker copy of a fact we
  already have.

  The `x5chain` route is the opposite case, and the reason the contrast is
  worth spelling out: there the unprotected header carries the *only* copy of
  the answer, and it is safe precisely because a wrong answer fails the
  signature check rather than passing a weaker one.

  ## Why a text label for the DID

  The integer header-parameter space is IANA-registered and 33 *is* `x5chain`,
  so putting a DID there would be claiming to be something we are not — a
  conformant reader would try to parse it as a certificate chain. A private
  text label is honest: a reader that does not know it ignores it and fails
  for the right reason (no trust anchor) rather than the wrong one.

  `frontend/packages/verification-sdk` resolves the issuer the same two ways.
  Keep them in step.
  """

  alias Sovra.Cbor
  alias Sovra.Mdl
  alias Sovra.Mdoc.DocType
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace
  alias Sovra.X509.Certificate

  @did_label "sovra_did"

  # RFC 9360 §2. ISO 18013-5 requires it in the unprotected header.
  @x5chain_label 33

  @doc "The label carrying the issuer reference. Exposed so tests can assert on it."
  def did_label, do: @did_label

  @doc "The COSE header parameter carrying the certificate chain (RFC 9360)."
  def x5chain_label, do: @x5chain_label

  @doc """
  The key to sign a credential of this docType with, and the `IssuerAuth`
  unprotected header that goes with it.

  The docType decides. A generated one is trusted through the address it
  carries, so it is signed by the workspace's general signing key — the same
  one its SD-JWTs use — and advertises the DID hint. An ISO one is trusted
  through its certificate, so it is signed by the key that certificate names
  and carries the certificate.

  `{:error, :document_signer_required}` when a schema names an ISO docType and
  the workspace has no registered signer. `Sovra.Issuer.Issuer` refuses that
  combination at schema creation and again at offer creation; this is the last
  line, and it fails rather than quietly falling back to a key no verifier
  would look for.
  """
  @spec issuer_auth_material(Workspace.t(), String.t()) ::
          {:ok, String.t(), map()} | {:error, term()}
  def issuer_auth_material(%Workspace{} = workspace, doc_type) when is_binary(doc_type) do
    case DocType.issuer_address(doc_type) do
      {:ok, _address} -> {:ok, workspace.signing_key_id, unprotected_header(workspace)}
      :error -> document_signer_material(workspace)
    end
  end

  defp document_signer_material(%Workspace{
         mdl_signing_key_id: key_id,
         mdl_signer_certificate: pem
       })
       when is_binary(key_id) and is_binary(pem) do
    with {:ok, certificate} <- Certificate.parse(pem) do
      {:ok, key_id, %{@x5chain_label => Cbor.bstr(certificate.der)}}
    end
  end

  defp document_signer_material(%Workspace{}), do: {:error, :document_signer_required}

  @doc """
  The `IssuerAuth` unprotected header for `workspace`, empty when it has no DID.

  Provisioning writes the EOA before the DID (`WorkspaceProvisioningJob.run/3`),
  and each step persists, so a retry between the two leaves a workspace that can
  build a docType but has no DID to advertise. Since nothing verifies through
  this header, a credential issued without it is exactly as valid — raising here
  would block issuance over a decoration, and as a `FunctionClauseError` deep
  inside CBOR encoding rather than as a named failure.
  """
  @spec unprotected_header(Workspace.t()) :: map()
  def unprotected_header(%Workspace{did: did}) when is_binary(did) and did != "" do
    %{@did_label => did}
  end

  def unprotected_header(%Workspace{}), do: %{}

  @doc """
  Resolve the issuing workspace and the key its `IssuerAuth` should verify
  against.

  Both routes only say *which key to try*. What makes that safe is the caller's
  next two steps: verify the MSO signature against the returned key, then
  require the signed MSO to name the same docType the lookup used. Altering
  either input sends the lookup somewhere whose key cannot verify the
  signature. See `Sovra.Verification.Verifier.check_doc_type/3`.
  """
  @spec resolve(String.t(), Sovra.Cose.Sign1.parsed()) ::
          {:ok, Workspace.t(), {binary(), binary()}} | {:error, :unknown_issuer}
  def resolve(doc_type, issuer_auth) do
    case DocType.issuer_address(doc_type) do
      {:ok, address} -> resolve_by_address(address)
      :error -> resolve_by_chain(issuer_auth)
    end
  end

  defp resolve_by_address(address) do
    case Workspaces.get_workspace_by_eoa_address(address) do
      {:ok, %Workspace{signing_public_key_x: x, signing_public_key_y: y} = workspace}
      when is_binary(x) and is_binary(y) ->
        {:ok, workspace, {x, y}}

      _ ->
        {:error, :unknown_issuer}
    end
  end

  # The leaf is looked up by the key it certifies rather than by its own bytes,
  # so the value that selects the workspace is the same value the signature is
  # then checked against — there is no second field that could disagree with
  # the first. Registration guarantees the match exists
  # (`Certificate.certifies?/2`), and a unique index guarantees it is unique.
  defp resolve_by_chain(issuer_auth) do
    with {:ok, leaf_der} <- x5chain_leaf(issuer_auth),
         {:ok, leaf} <- Certificate.parse(leaf_der),
         {:ok, workspace} <- Mdl.get_workspace_by_document_signer(leaf.public_key),
         {:ok, authority} <- Mdl.get_issuing_authority(workspace.mdl_issuing_authority_id),
         {:ok, root} <- Certificate.parse(authority.certificate),
         :ok <- Certificate.validate_document_signer(leaf, root) do
      {:ok, workspace, leaf.public_key}
    else
      _ -> {:error, :unknown_issuer}
    end
  end

  # RFC 9360 §2: one certificate travels as a bare byte string, several as an
  # array of them, leaf first. Both forms are the conformant way to say their
  # own thing, so both are read; only the unprotected header is, because that
  # is where 18013-5 puts the chain.
  #
  # Anything past the leaf is ignored. Our chains are two levels by
  # construction (Annex B allows no intermediates), the root is one we admitted
  # rather than one the credential supplies, and reading a sender-supplied root
  # is how a chain-validating reader gets talked into trusting the sender.
  defp x5chain_leaf(%{unprotected: unprotected}) when is_map(unprotected) do
    case Map.get(unprotected, @x5chain_label) do
      [first | _] -> unwrap_bstr(first)
      value -> unwrap_bstr(value)
    end
  end

  defp x5chain_leaf(_), do: :error

  defp unwrap_bstr(%CBOR.Tag{tag: :bytes, value: der}) when is_binary(der), do: {:ok, der}
  defp unwrap_bstr(der) when is_binary(der), do: {:ok, der}
  defp unwrap_bstr(_), do: :error
end
