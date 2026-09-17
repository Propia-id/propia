defmodule Sovra.X509.CertificateTest do
  @moduledoc """
  Every Annex B rule this codebase enforces has a test here that violates
  exactly that rule, so the list below is the authoritative answer to "what do
  we actually check". Rules deliberately not enforced — the CRL distribution
  point, the IACA validity ceiling — have no test, and `Sovra.X509.Certificate`
  says why.
  """
  use ExUnit.Case, async: true

  alias Sovra.X509.Certificate
  alias SovraTest.MdlCertificates, as: Mint

  setup do
    authority = Mint.iaca(country: "ES", common_name: "Dirección General de Tráfico")
    {point, _private} = Mint.keypair_point()
    %{authority: authority, point: point}
  end

  defp parse!(pem_or_der) do
    {:ok, certificate} = Certificate.parse(pem_or_der)
    certificate
  end

  describe "parse/1" do
    test "reads PEM and DER to the same certificate", %{authority: authority} do
      assert parse!(authority.pem) == parse!(authority.der)
    end

    test "extracts the subject, including a UTF-8 common name", %{authority: authority} do
      certificate = parse!(authority.pem)

      assert certificate.subject.country == "ES"
      assert certificate.subject.common_name == "Dirección General de Tráfico"
      assert certificate.issuer.common_name == "Dirección General de Tráfico"
    end

    test "extracts the public key as an uncompressed point", %{
      authority: authority,
      point: {x, y} = point
    } do
      signer = Mint.document_signer(authority, point)
      assert parse!(signer.pem).public_key == {x, y}
    end

    test "extracts the extensions the profile turns on", %{authority: authority, point: point} do
      assert parse!(authority.pem).key_usage == [:keyCertSign, :cRLSign]
      assert parse!(authority.pem).basic_constraints == {true, 0}

      signer = parse!(Mint.document_signer(authority, point).pem)
      assert signer.key_usage == [:digitalSignature]
      assert Certificate.document_signer_eku() in signer.extended_key_usage
      assert signer.basic_constraints == {false, nil}
    end

    test "knows a root from a leaf", %{authority: authority, point: point} do
      assert parse!(authority.pem).self_signed?
      refute parse!(Mint.document_signer(authority, point).pem).self_signed?
    end

    test "rejects input that is not a certificate" do
      assert {:error, {:certificate, :malformed}} = Certificate.parse("not a certificate")
    end
  end

  describe "validate_iaca/2" do
    test "accepts a conformant root", %{authority: authority} do
      assert :ok = Certificate.validate_iaca(parse!(authority.pem))
    end

    test "rejects a root that is not self-signed", %{authority: authority, point: point} do
      signer = Mint.document_signer(authority, point)

      assert {:error, {:iaca_profile, :not_self_signed}} =
               Certificate.validate_iaca(parse!(signer.pem))
    end

    test "rejects a root outside its own validity window" do
      expired = Mint.iaca(not_before: Mint.days_from_now(-800), not_after: Mint.days_from_now(-1))
      assert {:error, {:iaca_profile, :expired}} = Certificate.validate_iaca(parse!(expired.pem))

      future = Mint.iaca(not_before: Mint.days_from_now(30), not_after: Mint.days_from_now(900))

      assert {:error, {:iaca_profile, :not_yet_valid}} =
               Certificate.validate_iaca(parse!(future.pem))
    end

    test "rejects a root that cannot sign certificates" do
      # Annex B requires keyCertSign and cRLSign. A root without them cannot do
      # the job the trust list is about to advertise it for.
      wrong = Mint.iaca(key_usage: [:digitalSignature])
      assert {:error, {:iaca_profile, :key_usage}} = Certificate.validate_iaca(parse!(wrong.pem))
    end

    test "rejects a root that is not marked as a CA" do
      require Record

      not_a_ca =
        Mint.iaca(basic_constraints: {:BasicConstraints, false, :asn1_NOVALUE})

      assert {:error, {:iaca_profile, :basic_constraints}} =
               Certificate.validate_iaca(parse!(not_a_ca.pem))
    end
  end

  describe "validate_document_signer/3" do
    test "accepts a conformant signer", %{authority: authority, point: point} do
      signer = Mint.document_signer(authority, point)

      assert :ok =
               Certificate.validate_document_signer(
                 parse!(signer.pem),
                 parse!(authority.pem)
               )
    end

    test "rejects a signer valid for longer than Annex B allows", %{
      authority: authority,
      point: point
    } do
      signer =
        Mint.document_signer(authority, point,
          not_before: Mint.days_from_now(-1),
          not_after: Mint.days_from_now(Certificate.max_document_signer_days() + 2)
        )

      assert {:error, {:dsc_profile, :validity_too_long}} =
               Certificate.validate_document_signer(parse!(signer.pem), parse!(authority.pem))
    end

    test "rejects a signer that claims to be a CA", %{authority: authority, point: point} do
      signer =
        Mint.document_signer(authority, point,
          basic_constraints: {:BasicConstraints, true, :asn1_NOVALUE}
        )

      assert {:error, {:dsc_profile, :is_a_ca}} =
               Certificate.validate_document_signer(parse!(signer.pem), parse!(authority.pem))
    end

    test "rejects a signer without digitalSignature alone", %{authority: authority, point: point} do
      signer =
        Mint.document_signer(authority, point, key_usage: [:digitalSignature, :keyCertSign])

      assert {:error, {:dsc_profile, :key_usage}} =
               Certificate.validate_document_signer(parse!(signer.pem), parse!(authority.pem))
    end

    test "rejects a signer that is not marked for mDL signing", %{
      authority: authority,
      point: point
    } do
      # Without `id-mdlDS` a reader has no reason to believe this key was meant
      # to sign mobile documents, whatever else the chain proves.
      signer =
        Mint.document_signer(authority, point, extended_key_usage: [{1, 3, 6, 1, 5, 5, 7, 3, 1}])

      assert {:error, {:dsc_profile, :missing_mdl_eku}} =
               Certificate.validate_document_signer(parse!(signer.pem), parse!(authority.pem))
    end

    test "rejects a signer from another country", %{authority: authority, point: point} do
      signer = Mint.document_signer(authority, point, country: "FR")

      assert {:error, {:dsc_profile, :country_mismatch}} =
               Certificate.validate_document_signer(parse!(signer.pem), parse!(authority.pem))
    end

    test "rejects a signer whose chain does not lead to this root", %{point: point} do
      one = Mint.iaca(common_name: "Authority One")
      other = Mint.iaca(common_name: "Authority Two")
      signer = Mint.document_signer(one, point)

      assert {:error, {:dsc_profile, {:chain, _}}} =
               Certificate.validate_document_signer(parse!(signer.pem), parse!(other.pem))
    end
  end

  describe "state agreement — the federated case" do
    test "a root that names no state certifies signers that each name their own" do
      # Spain's root with one signer per region: the shape the whole
      # state-matching rule exists to allow.
      national = Mint.iaca(country: "ES", state: nil, common_name: "Spain IACA")

      for region <- ["Cataluña", "Madrid", "Euskadi"] do
        {point, _private} = Mint.keypair_point()
        signer = Mint.document_signer(national, point, country: "ES", state: region)

        assert :ok =
                 Certificate.validate_document_signer(parse!(signer.pem), parse!(national.pem))
      end
    end

    test "a root that names a state constrains its signers to it" do
      regional = Mint.iaca(country: "ES", state: "Madrid", common_name: "Madrid IACA")
      {point, _private} = Mint.keypair_point()
      signer = Mint.document_signer(regional, point, country: "ES", state: "Cataluña")

      assert {:error, {:dsc_profile, :state_mismatch}} =
               Certificate.validate_document_signer(parse!(signer.pem), parse!(regional.pem))
    end
  end

  describe "certifies?/2" do
    test "is the check that matters: the certificate names our key", %{
      authority: authority,
      point: point
    } do
      signer = parse!(Mint.document_signer(authority, point).pem)
      {other_point, _private} = Mint.keypair_point()

      assert Certificate.certifies?(signer, point)

      # A perfectly valid chain that certifies somebody else's key. Nothing in
      # the profile catches this, which is why it is checked separately.
      refute Certificate.certifies?(signer, other_point)
    end
  end
end
