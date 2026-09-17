defmodule SovraTest.MdlCertificates do
  @moduledoc """
  An issuing authority simulator: mints an IACA root and the Document Signer
  Certificates it issues, to whatever profile a test needs.

  Built rather than committed as fixtures for one reason. A Document Signer
  Certificate is capped at 457 days by Annex B, and `pkix_path_validation`
  checks dates against the system clock — so any certificate checked into the
  tree would start failing about a year after it was generated, in a way that
  looks like a code regression. Minting per test keeps the suite hermetic and
  lets a test place a certificate deliberately outside its own window.

  `:public_key.pkix_sign/2` does the encoding, which is safe here in a way it is
  not for PKCS#10: OTP encodes certificates fully. `Sovra.X509.Csr` documents
  why the request path had to be hand-rolled instead.
  """

  require Record

  Record.defrecordp(
    :tbs,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :validity,
    :Validity,
    Record.extract(:Validity, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :spki,
    :OTPSubjectPublicKeyInfo,
    Record.extract(:OTPSubjectPublicKeyInfo, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :public_key_algorithm,
    :PublicKeyAlgorithm,
    Record.extract(:PublicKeyAlgorithm, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :signature_algorithm,
    :SignatureAlgorithm,
    Record.extract(:SignatureAlgorithm, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :extension,
    :Extension,
    Record.extract(:Extension, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :basic_constraints,
    :BasicConstraints,
    Record.extract(:BasicConstraints, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :attribute,
    :AttributeTypeAndValue,
    Record.extract(:AttributeTypeAndValue, from_lib: "public_key/include/public_key.hrl")
  )

  @secp256r1 {1, 2, 840, 10045, 3, 1, 7}
  @id_ec_public_key {1, 2, 840, 10045, 2, 1}
  @ecdsa_with_sha256 {1, 2, 840, 10045, 4, 3, 2}

  @oid_common_name {2, 5, 4, 3}
  @oid_country {2, 5, 4, 6}
  @oid_state {2, 5, 4, 8}

  @oid_key_usage {2, 5, 29, 15}
  @oid_extended_key_usage {2, 5, 29, 37}
  @oid_basic_constraints {2, 5, 29, 19}

  @mdl_document_signer_eku {1, 0, 18013, 5, 1, 2}

  @doc """
  Mint a self-signed IACA root.

  Options: `:country`, `:state`, `:common_name`, `:not_before`, `:not_after`,
  plus `:key_usage` and `:basic_constraints` for tests that need a root that
  breaks the profile on purpose.
  """
  def iaca(opts \\ []) do
    {public, private} = keypair()
    country = Keyword.get(opts, :country, "ES")

    name =
      subject(country, Keyword.get(opts, :state), Keyword.get(opts, :common_name, "Test IACA"))

    not_before = Keyword.get(opts, :not_before, days_from_now(-1))
    not_after = Keyword.get(opts, :not_after, days_from_now(7300))

    extensions = [
      extension(
        extnID: @oid_basic_constraints,
        critical: true,
        extnValue:
          Keyword.get(opts, :basic_constraints, basic_constraints(cA: true, pathLenConstraint: 0))
      ),
      extension(
        extnID: @oid_key_usage,
        critical: true,
        extnValue: Keyword.get(opts, :key_usage, [:keyCertSign, :cRLSign])
      )
    ]

    der =
      sign(
        %{
          serial: 1,
          issuer: name,
          subject: name,
          public: public,
          not_before: not_before,
          not_after: not_after,
          extensions: extensions
        },
        private,
        public
      )

    %{der: der, pem: pem(der), public_key: public, private_key: private, subject: name}
  end

  @doc """
  Mint a Document Signer Certificate under `authority`, for `{x, y}`.

  Defaults to a conformant profile; every rule Annex B imposes is an option, so
  a test can violate exactly one and assert on the specific failure.
  """
  def document_signer(authority, {x, y}, opts \\ []) do
    country = Keyword.get(opts, :country, "ES")

    name =
      subject(
        country,
        Keyword.get(opts, :state),
        Keyword.get(opts, :common_name, "Test Document Signer")
      )

    not_before = Keyword.get(opts, :not_before, days_from_now(-1))
    not_after = Keyword.get(opts, :not_after, days_from_now(400))

    extensions =
      [
        extension(
          extnID: @oid_key_usage,
          critical: true,
          extnValue: Keyword.get(opts, :key_usage, [:digitalSignature])
        ),
        extension(
          extnID: @oid_extended_key_usage,
          critical: true,
          extnValue: Keyword.get(opts, :extended_key_usage, [@mdl_document_signer_eku])
        )
      ] ++ maybe_basic_constraints(opts)

    der =
      sign(
        %{
          serial: Keyword.get(opts, :serial, 2),
          issuer: authority.subject,
          subject: name,
          public: <<0x04>> <> x <> y,
          not_before: not_before,
          not_after: not_after,
          extensions: extensions
        },
        authority.private_key,
        authority.public_key
      )

    %{der: der, pem: pem(der), subject: name}
  end

  @doc """
  Take a provisioned workspace all the way to being able to issue under an ISO
  docType: generate its document signer key, admit a fresh IACA root, and
  register a certificate that root issued for that key.

  The whole registration flow, not a shortcut past it — the test is then
  exercising the same workspace state production produces, including the
  `certifies?/2` check that ties the certificate to the key.

  Options are passed through to `document_signer/3`, so a test can register a
  certificate that is about to expire, or one for somebody else's key.

  Returns the reloaded workspace alongside the root and certificate, because a
  test that wants to substitute a chain needs the DER it was given.
  """
  def provision_document_signer(workspace, opts \\ []) do
    {:ok, workspace} = Sovra.Mdl.create_signing_key(workspace.id)

    authority_certificate = iaca()
    {:ok, authority} = Sovra.Mdl.admit_issuing_authority(authority_certificate.pem, nil)

    key = {workspace.mdl_signing_public_key_x, workspace.mdl_signing_public_key_y}
    signer = document_signer(authority_certificate, Keyword.get(opts, :key, key), opts)

    {:ok, workspace} = Sovra.Mdl.register_document_signer(workspace.id, authority.id, signer.pem)

    %{
      workspace: workspace,
      authority: authority,
      iaca: authority_certificate,
      document_signer: signer
    }
  end

  @doc "A fresh P-256 keypair as `{{x, y}, private}`, for a signer under test."
  def keypair_point do
    {<<0x04, x::binary-size(32), y::binary-size(32)>>, private} = keypair()
    {{x, y}, private}
  end

  # ── Internals ───────────────────────────────────────────

  defp keypair, do: :crypto.generate_key(:ecdh, :secp256r1)

  defp maybe_basic_constraints(opts) do
    case Keyword.get(opts, :basic_constraints, :default) do
      :default ->
        [
          extension(
            extnID: @oid_basic_constraints,
            critical: true,
            extnValue: basic_constraints(cA: false, pathLenConstraint: :asn1_NOVALUE)
          )
        ]

      nil ->
        []

      value ->
        [extension(extnID: @oid_basic_constraints, critical: true, extnValue: value)]
    end
  end

  defp subject(country, state, common_name) do
    rdns =
      [
        {@oid_country, String.to_charlist(country)},
        {@oid_state, state && {:utf8String, state}},
        {@oid_common_name, {:utf8String, common_name}}
      ]
      |> Enum.reject(fn {_oid, value} -> is_nil(value) end)
      |> Enum.map(fn {oid, value} -> [attribute(type: oid, value: value)] end)

    {:rdnSequence, rdns}
  end

  defp sign(fields, private, issuer_public) do
    certificate =
      tbs(
        version: :v3,
        serialNumber: fields.serial,
        signature: signature_algorithm(algorithm: @ecdsa_with_sha256, parameters: :asn1_NOVALUE),
        issuer: fields.issuer,
        validity: validity(notBefore: fields.not_before, notAfter: fields.not_after),
        subject: fields.subject,
        subjectPublicKeyInfo:
          spki(
            algorithm:
              public_key_algorithm(
                algorithm: @id_ec_public_key,
                parameters: {:namedCurve, @secp256r1}
              ),
            subjectPublicKey: {:ECPoint, fields.public}
          ),
        extensions: fields.extensions
      )

    :public_key.pkix_sign(
      certificate,
      {:ECPrivateKey, 1, private, {:namedCurve, @secp256r1}, issuer_public, :asn1_NOVALUE}
    )
  end

  defp pem(der), do: :public_key.pem_encode([{:Certificate, der, :not_encrypted}])

  @doc "A UTCTime the given number of days from now, for placing a validity window."
  def days_from_now(days) do
    DateTime.utc_now()
    |> DateTime.add(days * 86_400, :second)
    |> then(&{:utcTime, String.to_charlist(Calendar.strftime(&1, "%y%m%d%H%M%SZ"))})
  end
end
