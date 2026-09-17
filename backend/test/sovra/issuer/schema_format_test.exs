defmodule Sovra.Issuer.SchemaFormatTest do
  use Sovra.DataCase, async: false

  alias Sovra.Issuer
  alias Sovra.Issuer.CredentialSchema
  alias Sovra.Mdoc.DocType

  setup do
    %{workspace: ws} = fixture_workspace()
    {:ok, workspace: provision_workspace(ws)}
  end

  defp attrs(overrides \\ %{}) do
    Map.merge(
      %{
        schema_id: "membership-card-#{System.unique_integer([:positive])}",
        credential_type: "MembershipCard",
        name: "Membership Card",
        claims: [
          %{
            "key" => "member_name",
            "type" => "string",
            "required" => true,
            "disclosable" => true
          },
          %{"key" => "tier", "type" => "string", "required" => true, "disclosable" => false}
        ],
        validity_period: "1y"
      },
      overrides
    )
  end

  # The ISO namespace is a closed element set, so a schema in it cannot carry
  # `member_name` or `tier` — see `Sovra.Mdl.Template`.
  defp iso_claims do
    [
      %{"key" => "family_name", "type" => "string", "required" => true, "disclosable" => true},
      %{
        "key" => "document_number",
        "type" => "string",
        "required" => true,
        "disclosable" => false
      }
    ]
  end

  describe "format on creation" do
    test "defaults to vc+sd-jwt", %{workspace: ws} do
      {:ok, schema} = Issuer.create_schema(ws.id, attrs())
      assert schema.format == "vc+sd-jwt"
    end

    test "accepts mso_mdoc", %{workspace: ws} do
      {:ok, schema} = Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc"}))
      assert schema.format == "mso_mdoc"
    end

    test "rejects an unknown format", %{workspace: ws} do
      {:error, changeset} = Issuer.create_schema(ws.id, attrs(%{format: "jwt_vc_json"}))
      assert "is invalid" in errors_on(changeset).format
    end

    test "rejects mdoc on a document schema", %{workspace: ws} do
      # Enforced by a DB check constraint, so this combination is
      # unrepresentable rather than merely discouraged.
      {:error, changeset} =
        Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc", kind: "document"}))

      assert "mdoc is only available for credential schemas" in errors_on(changeset).format
    end

    test "rejects a schema_id that would corrupt the docType", %{workspace: ws} do
      # A dot would silently add a level to the generated docType.
      {:error, changeset} =
        Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc", schema_id: "member.card"}))

      assert changeset.errors[:schema_id]

      {:error, changeset} =
        Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc", schema_id: "Member Card"}))

      assert changeset.errors[:schema_id]
    end

    test "leaves existing sd-jwt schema_ids alone", %{workspace: ws} do
      # The schema_id rule is conditional on the format precisely so adding
      # mdoc does not retro-invalidate identifiers already in use.
      {:ok, schema} = Issuer.create_schema(ws.id, attrs(%{schema_id: "Legacy.Schema ID"}))
      assert schema.schema_id == "Legacy.Schema ID"
    end
  end

  describe "format across revisions" do
    test "is carried forward, not taken from the request", %{workspace: ws} do
      {:ok, schema} = Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc"}))

      {:ok, revised} =
        Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
          name: "Renamed",
          claims: schema.claims,
          validity_period: "2y",
          # Ignored: flipping the format would orphan every credential already
          # issued under the old docType.
          format: "vc+sd-jwt"
        })

      assert revised.version == schema.version + 1
      assert revised.format == "mso_mdoc"
      assert revised.name == "Renamed"
    end

    test "an sd-jwt schema cannot be promoted to mdoc by revision", %{workspace: ws} do
      {:ok, schema} = Issuer.create_schema(ws.id, attrs())

      {:ok, revised} =
        Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
          name: schema.name,
          claims: schema.claims,
          validity_period: "1y",
          format: "mso_mdoc"
        })

      assert revised.format == "vc+sd-jwt"
    end

    test "a revision cannot introduce an ISO docType", %{workspace: ws} do
      # `create_schema/2` refuses an ISO docType without a registered document
      # signer, and a revision is not a creation — so without pinning, this is
      # the way around that check. It would also orphan every credential already
      # issued under the generated docType.
      {:ok, schema} = Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc"}))
      assert is_nil(schema.doc_type)

      {:ok, revised} =
        Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
          name: schema.name,
          claims: schema.claims,
          validity_period: "1y",
          doc_type: "org.iso.18013.5.1.mDL",
          namespace: "org.iso.18013.5.1"
        })

      assert is_nil(revised.doc_type)
      assert is_nil(revised.namespace)
    end

    test "a revision cannot drop the ISO docType a schema was created with", %{workspace: ws} do
      # The same orphaning in the other direction: credentials in wallets name
      # the ISO docType, and a revision that silently reverted to a generated
      # one would make our own verifier reject them.
      %{workspace: ws} = SovraTest.MdlCertificates.provision_document_signer(ws)

      {:ok, schema} =
        Issuer.create_schema(
          ws.id,
          attrs(%{
            format: "mso_mdoc",
            doc_type: "org.iso.18013.5.1.mDL",
            namespace: "org.iso.18013.5.1",
            claims: iso_claims()
          })
        )

      {:ok, revised} =
        Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
          name: schema.name,
          claims: schema.claims,
          validity_period: "1y",
          doc_type: nil,
          namespace: nil
        })

      assert revised.doc_type == "org.iso.18013.5.1.mDL"
      assert revised.namespace == "org.iso.18013.5.1"
    end
  end

  describe "assert_format/2" do
    test "passes on a match and names the actual format on a mismatch" do
      schema = %CredentialSchema{format: "mso_mdoc"}

      assert :ok = CredentialSchema.assert_format(schema, "mso_mdoc")

      assert {:error, {:wrong_schema_format, "mso_mdoc"}} =
               CredentialSchema.assert_format(schema, "vc+sd-jwt")
    end
  end

  describe "docType generation" do
    test "derives from the provisioned workspace and the schema_id", %{workspace: ws} do
      {:ok, schema} =
        Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc", schema_id: "membership-card"}))

      assert DocType.build(ws, schema) ==
               "io.sovra.#{String.downcase(ws.eoa_address)}.membership-card.1"

      assert DocType.issuer_address(DocType.build(ws, schema)) ==
               {:ok, String.downcase(ws.eoa_address)}
    end

    test "survives a revision unchanged", %{workspace: ws} do
      {:ok, schema} =
        Issuer.create_schema(ws.id, attrs(%{format: "mso_mdoc", schema_id: "membership-card"}))

      {:ok, revised} =
        Issuer.revise_schema(ws.id, schema.schema_id, schema.version, %{
          name: "v2",
          claims: schema.claims,
          validity_period: "1y"
        })

      # The whole point of freezing format and schema_id: already-issued
      # credentials keep matching queries built from the current schema.
      assert DocType.build(ws, revised) == DocType.build(ws, schema)
    end
  end
end
