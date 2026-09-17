defmodule Mix.Tasks.Sovra.MdlCertificateFixture do
  @shortdoc "Regenerate the mDL certificate fixtures the verification SDK reads"

  @moduledoc """
  Regenerates
  `frontend/packages/verification-sdk/test/fixtures/mdl-certificates.json`.

  `frontend/packages/verification-sdk/src/x509.ts` parses and path-validates an
  mDL chain in TypeScript. These fixtures are what it is tested against, minted
  here so the certificates it reads are ones this backend's own minter produced
  — the same reasoning as `mix sovra.mdoc_fixture`, applied to X.509 instead of
  CBOR. A TypeScript parser tested only against TypeScript-built certificates
  proves the two halves of one misreading agree with each other.

  ## Why the windows are fixed dates

  `SovraTest.MdlCertificates` mints relative windows, because
  `:public_key.pkix_path_validation/3` checks against the system clock and a
  committed certificate would start failing about a year from now, looking like
  a regression.

  TypeScript solves it the other way round: `validateDocumentSignerChain/3`
  takes `now`, so the fixtures carry absolute windows and the tests pin the
  clock to `validAt`. The certificates never expire because the test decides
  what time it is.

      mix sovra.mdl_certificate_fixture

  Run it when the Annex B profile checks change, and commit the result.
  """

  use Mix.Task

  alias Sovra.Crypto.Key
  alias Sovra.Crypto.P256
  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Issuer.Mdoc
  alias Sovra.Mdl.Template
  alias Sovra.Workspaces.Workspace

  @output "../frontend/packages/verification-sdk/test/fixtures/mdl-certificates.json"

  # 2026-01-01 to 2036-01-01 for a root, and one year for a signer — inside
  # Annex B's 457-day cap, with `@valid_at` sitting in the middle of both.
  @iaca_from "260101000000Z"
  @iaca_until "360101000000Z"
  @signer_from "260101000000Z"
  @signer_until "270101000000Z"
  @valid_at 1_780_000_000

  # Fixed so the fixture only changes when the structure does, and inside both
  # certificate windows so a test pinning its clock to `@valid_at` sees a
  # credential that is current.
  @issuer_address "0xAb34Cd09F900112233445566778899aAbBcCdDeE"
  @holder_did "did:sovra:0xholder"
  @signed_at ~U[2026-03-01 00:00:00Z]
  @status_list_index 42

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")
    Code.require_file("test/support/mdl_certificates.ex")

    authority =
      minter().iaca(
        country: "ES",
        common_name: "Test IACA",
        not_before: utc(@iaca_from),
        not_after: utc(@iaca_until)
      )

    stranger =
      minter().iaca(
        country: "ES",
        common_name: "Stranger IACA",
        not_before: utc(@iaca_from),
        not_after: utc(@iaca_until)
      )

    # A root that *calls itself* the admitted one. Its subject DER is identical,
    # so a validator matching anchors by name finds it — and its key is not the
    # admitted key, so the signature must be what refuses it. Anyone can mint
    # this; the whole point is that naming yourself Spain proves nothing.
    impostor =
      minter().iaca(
        country: "ES",
        common_name: "Test IACA",
        not_before: utc(@iaca_from),
        not_after: utc(@iaca_until)
      )

    {{x, y}, _private} = minter().keypair_point()
    {{stranger_x, stranger_y}, _} = minter().keypair_point()
    {{impostor_x, impostor_y}, _} = minter().keypair_point()

    signer = fn opts ->
      {auth, opts} = Keyword.pop(opts, :authority, authority)
      {key, opts} = Keyword.pop(opts, :key, {x, y})

      minter().document_signer(
        auth,
        key,
        Keyword.merge([not_before: utc(@signer_from), not_after: utc(@signer_until)], opts)
      )
    end

    fixture = %{
      "validAt" => @valid_at,
      "iaca" => %{"der" => der(authority), "pem" => authority.pem},
      "documentSigner" => %{
        "der" => der(signer.([])),
        "pem" => signer.([]).pem,
        "publicKey" => %{"x" => hex(x), "y" => hex(y)}
      },
      "strangerIaca" => %{"der" => der(stranger)},
      "impostorSigner" => %{
        "der" => der(signer.(authority: impostor, key: {impostor_x, impostor_y}))
      },
      # Valid in itself, under a root the caller never admitted.
      "strangerSigner" => %{
        "der" => der(signer.(authority: stranger, key: {stranger_x, stranger_y}))
      },
      # The failure registration cannot catch, since it did not exist then.
      "expiredSigner" => %{
        "der" => der(signer.(not_before: utc("240101000000Z"), not_after: utc("240601000000Z")))
      },
      "tooLongSigner" => %{"der" => der(signer.(not_after: utc("270701000000Z")))},
      "noEkuSigner" => %{"der" => der(signer.(extended_key_usage: []))},
      "caSigner" => %{
        "der" => der(signer.(basic_constraints: {:BasicConstraints, true, :asn1_NOVALUE}))
      },
      "wrongCountrySigner" => %{"der" => der(signer.(country: "FR"))},
      "wrongKeyUsageSigner" => %{
        "der" => der(signer.(key_usage: [:digitalSignature, :keyCertSign]))
      },
      "mdl" => mdl(authority)
    }

    path = Path.expand(@output, File.cwd!())
    File.write!(path, Jason.encode!(fixture, pretty: true) <> "\n")
    Mix.shell().info("wrote #{path}")
  end

  # A whole mDL, issued the way `Sovra.Issuer.Mdoc` issues one under an ISO
  # docType: signed by the document signer key, carrying that certificate in
  # `x5chain`, with the data elements in the ISO namespace.
  #
  # The SDK's end-to-end test verifies this, which is what proves its routing —
  # an ISO docType takes the certificate route, and the key it verifies against
  # comes from the chain rather than from any address.
  defp mdl(authority) do
    {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} =
      Key.generate_key("mdl-fixture-document-signer")

    certificate =
      minter().document_signer(authority, {x, y},
        not_before: utc(@signer_from),
        not_after: utc(@signer_until)
      )

    workspace = %Workspace{
      eoa_address: @issuer_address,
      did: "did:sovra:" <> String.downcase(@issuer_address),
      mdl_signing_key_id: key_id,
      mdl_signing_public_key_x: x,
      mdl_signing_public_key_y: y,
      mdl_signer_certificate: certificate.pem
    }

    {:ok, holder} = P256.generate_key_pair()
    schema = mdl_schema()

    {:ok, built} =
      Mdoc.build(
        workspace,
        schema,
        mdl_claims(),
        @holder_did,
        {holder.public_key_x, holder.public_key_y},
        status_list_index: @status_list_index,
        now: @signed_at
      )

    %{
      "credentialType" => schema.credential_type,
      "docType" => built.doc_type,
      "namespace" => Template.namespace(),
      "issuerAddress" => String.downcase(@issuer_address),
      "holderDid" => @holder_did,
      "holderPrivateKey" => hex(holder.private_key),
      "holderPublicKey" => %{
        "x" => hex(holder.public_key_x),
        "y" => hex(holder.public_key_y)
      },
      "documentSignerPem" => certificate.pem,
      "issuerSigned" => built.credential,
      "signedAt" => DateTime.to_iso8601(@signed_at),
      "statusListIndex" => @status_list_index
    }
  end

  # Every element ISO makes mandatory, which is what a reader is entitled to
  # expect from something calling itself an mDL.
  defp mdl_schema do
    %CredentialSchema{
      schema_id: "mdl",
      credential_type: "DrivingLicence",
      name: "Driving Licence",
      format: "mso_mdoc",
      doc_type: Template.doc_type(),
      namespace: Template.namespace(),
      validity_period: "1y",
      claims: Template.claim_definitions()
    }
  end

  defp mdl_claims do
    %{
      "family_name" => "Lovelace",
      "given_name" => "Ada",
      "birth_date" => "1815-12-10",
      "issue_date" => "2026-01-05",
      "expiry_date" => "2036-01-05",
      "issuing_country" => "ES",
      "issuing_authority" => "Test IACA",
      "document_number" => "D-1234567",
      "portrait" => Base.encode64(<<0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46>>),
      "un_distinguishing_sign" => "E",
      "age_over_18" => true,
      "driving_privileges" => [
        %{
          "vehicle_category_code" => "B",
          "issue_date" => "2026-01-05",
          "expiry_date" => "2036-01-05"
        }
      ]
    }
  end

  # `SovraTest.MdlCertificates` lives in `test/support`, which a dev-environment
  # compile cannot see — a literal alias would warn there even though the task
  # loads the file before using it. Resolved through a function so the call is
  # dynamic dispatch, which the compiler does not try to check.
  defp minter, do: Module.concat([SovraTest, MdlCertificates])

  defp utc(value), do: {:utcTime, String.to_charlist(value)}
  defp der(%{der: der}), do: Base.encode64(der)
  defp hex(binary), do: Base.encode16(binary, case: :lower)
end
