defmodule Sovra.X509.Csr do
  @moduledoc """
  PKCS#10 certification requests for a workspace key that never leaves KMS.

  ## Why this exists

  Issuing a real mDL means the MSO is signed by a key an issuing authority has
  certified, because third-party readers trust that authority's root from a
  trust list they already hold. So the authority has to certify *our* key — and
  the private half is in KMS, where it cannot be handed over for a certificate
  to be built around it.

  A certification request is the standard answer. It carries the public key and
  the requested subject, self-signed to prove possession of the private half.
  The operator takes it to their IACA and returns with a Document Signer
  Certificate; the private key never exists outside KMS at any point.

  ## Why the DER is assembled here

  `:public_key` cannot encode this. PKCS-10's ASN.1 information-object set has
  no `id-ecPublicKey` entry, so `der_encode(:CertificationRequest, ...)` fails
  on any EC key — while `der_decode/2` reads one back without complaint, which
  is what `Sovra.X509.CsrTest` verifies against.

  The subject and key info are encoded by hand too, for a different reason:
  which ASN.1 module `:public_key` dispatches `:Name` to varies by OTP release,
  and they disagree about whether an attribute value arrives decoded or as
  bytes. Encoding the whole structure through `Sovra.X509.Der` is version-proof
  and, since these bytes get signed, worth the twenty lines.

  Signing stays external throughout: the `CertificationRequestInfo` DER is built
  first, hashed, and signed through `Sovra.Crypto.Key.sign/2` — the same seam
  every other Sovra signature uses — and only then wrapped.
  """

  alias Sovra.Crypto.Key
  alias Sovra.X509.Der

  @id_ec_public_key {1, 2, 840, 10045, 2, 1}
  @secp256r1 {1, 2, 840, 10045, 3, 1, 7}
  @ecdsa_with_sha256 {1, 2, 840, 10045, 4, 3, 2}

  @oid_common_name {2, 5, 4, 3}
  @oid_country {2, 5, 4, 6}
  @oid_state {2, 5, 4, 8}
  @oid_organization {2, 5, 4, 10}

  @typedoc """
  The subject to request.

  `:country` and `:common_name` are required because ISO/IEC 18013-5 Annex B
  requires both on a Document Signer Certificate. `:state` is the one that
  matters for a federated authority: an IACA that declares no state can certify
  signers that each name their own region.
  """
  @type subject :: [
          country: String.t(),
          common_name: String.t(),
          state: String.t() | nil,
          organization: String.t() | nil
        ]

  @doc """
  Build a PEM certification request for `signing_key_id`.

  `public_key` is the `{x, y}` P-256 point of that same key, passed in rather
  than read back from the key store because every caller already holds it on
  the workspace record.
  """
  @spec build(String.t(), {binary(), binary()}, subject()) ::
          {:ok, String.t()} | {:error, term()}
  def build(signing_key_id, {x, y}, subject)
      when is_binary(signing_key_id) and is_binary(x) and is_binary(y) do
    with {:ok, name} <- encode_subject(subject),
         info = request_info(name, x, y),
         {:ok, signature} <- sign(signing_key_id, info) do
      der =
        Der.sequence([
          info,
          Der.sequence([Der.oid(@ecdsa_with_sha256)]),
          Der.bit_string(signature)
        ])

      {:ok, :public_key.pem_encode([{:CertificationRequest, der, :not_encrypted}])}
    end
  end

  # ── Structure ───────────────────────────────────────────

  # CertificationRequestInfo ::= SEQUENCE {
  #   version INTEGER, subject Name, subjectPKInfo SubjectPublicKeyInfo,
  #   attributes [0] IMPLICIT SET OF Attribute }
  #
  # The attributes set is empty but structurally required — a CA that looked for
  # requested extensions would reject a request missing the slot outright.
  defp request_info(name, x, y) do
    Der.sequence([
      Der.integer(0),
      name,
      public_key_info(x, y),
      Der.context(0, [])
    ])
  end

  # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
  # For EC the algorithm parameters carry the named curve, and the key is an
  # uncompressed point — the only form 18013-5 uses.
  defp public_key_info(x, y) do
    Der.sequence([
      Der.sequence([Der.oid(@id_ec_public_key), Der.oid(@secp256r1)]),
      Der.bit_string(<<0x04>> <> x <> y)
    ])
  end

  # ── Subject ─────────────────────────────────────────────

  # Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName,
  # each of which is a SET OF AttributeTypeAndValue.
  defp encode_subject(subject) do
    with {:ok, country} <- fetch_country(subject),
         {:ok, common_name} <- fetch_required(subject, :common_name) do
      rdns =
        [
          {@oid_country, Der.printable_string(country)},
          {@oid_state, utf8(Keyword.get(subject, :state))},
          {@oid_organization, utf8(Keyword.get(subject, :organization))},
          {@oid_common_name, Der.utf8_string(common_name)}
        ]
        |> Enum.reject(fn {_oid, value} -> is_nil(value) end)
        |> Enum.map(fn {oid, value} -> Der.set([Der.sequence([Der.oid(oid), value])]) end)

      {:ok, Der.sequence(rdns)}
    end
  end

  defp utf8(value) do
    if blank?(value), do: nil, else: Der.utf8_string(value)
  end

  # ISO 3166-1 alpha-2, which Annex B requires and which a CA rejects anything
  # else for. Checked here so the failure names the field rather than surfacing
  # after the operator has already taken the request away.
  defp fetch_country(subject) do
    case Keyword.get(subject, :country) do
      code when is_binary(code) ->
        if Regex.match?(~r/^[A-Z]{2}$/, code),
          do: {:ok, code},
          else: {:error, {:invalid_subject, :country}}

      _ ->
        {:error, {:missing_subject_field, :country}}
    end
  end

  defp fetch_required(subject, field) do
    value = Keyword.get(subject, field)

    if blank?(value), do: {:error, {:missing_subject_field, field}}, else: {:ok, value}
  end

  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: true

  # ── Signing ─────────────────────────────────────────────

  defp sign(signing_key_id, info) do
    case Key.sign(signing_key_id, :crypto.hash(:sha256, info)) do
      {:ok, %{r: r, s: s}} -> {:ok, Der.ecdsa_signature(r, s)}
      {:error, _} = error -> error
    end
  end
end
