defmodule Sovra.Issuer.OID4VCITest do
  use Sovra.DataCase, async: true

  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.OID4VCI
  alias Sovra.Organizations
  alias Sovra.Workspaces.Workspace

  defp build_workspace(attrs) do
    # Build a non-persisted workspace with only the fields OID4VCI needs.
    struct(
      Workspace,
      Map.merge(%{name: "Fallback", organization: nil, did: "did:sovra:0xfallback"}, attrs)
    )
  end

  describe "build_metadata/2 issuer identity" do
    test "credential_issuer is the workspace-scoped HTTPS identifier" do
      workspace = build_workspace(%{did: "did:sovra:0xabc"})

      metadata = OID4VCI.build_metadata(workspace, [])

      assert metadata["credential_issuer"] == "#{ClaimUtils.base_url()}/did:sovra:0xabc"
    end

    test "authorization_servers points back at the credential_issuer" do
      workspace = build_workspace(%{did: "did:sovra:0xabc"})

      metadata = OID4VCI.build_metadata(workspace, [])

      assert metadata["authorization_servers"] == [metadata["credential_issuer"]]
    end

    test "token_endpoint is not advertised on issuer metadata (lives on AS metadata)" do
      workspace = build_workspace(%{did: "did:sovra:0xabc"})

      metadata = OID4VCI.build_metadata(workspace, [])

      refute Map.has_key?(metadata, "token_endpoint")
    end
  end

  describe "build_metadata/2 display entry" do
    test "falls back to workspace name when workspace has no organization" do
      workspace = build_workspace(%{name: "Solo"})

      metadata = OID4VCI.build_metadata(workspace, [])

      assert metadata["display"] == [%{"name" => "Solo"}]
    end

    test "surfaces organization name, logo, and website when present" do
      owner =
        %Sovra.Accounts.User{}
        |> Sovra.Accounts.User.admin_changeset(%{
          email: "owner-#{System.unique_integer([:positive])}@example.com",
          password: "a-very-strong-password-123"
        })
        |> Sovra.Repo.insert!()

      {:ok, %{organization: org}} =
        Organizations.create_organization(owner.id, %{
          name: "Branded",
          logo_url: "https://branded.test/logo.png",
          website: "https://branded.test"
        })

      # Persist a workspace linked to the org so preload works.
      {:ok, workspace} =
        Sovra.Repo.insert(%Workspace{
          name: "Should be ignored",
          eoa_address: "0x" <> String.duplicate("cd", 20),
          eoa_key_id: "ek-#{System.unique_integer([:positive])}",
          signing_key_id: "sk-#{System.unique_integer([:positive])}",
          signing_public_key_x: <<1::256>>,
          signing_public_key_y: <<2::256>>,
          did:
            "did:sovra:0x#{Base.encode16(<<System.unique_integer([:positive])::256>>, case: :lower)}",
          organization_id: org.id,
          status_index_secret_key_id: "stub-#{System.unique_integer([:positive])}"
        })

      {:ok, schema} =
        Sovra.Issuer.CredentialSchema.create_changeset(%{
          schema_id: "branded-schema-#{System.unique_integer([:positive])}",
          issuer_id: workspace.id,
          credential_type: "BrandedCredential",
          name: "Branded Credential",
          claims: [%{"key" => "name", "type" => "string", "required" => true}],
          validity_period: "1y"
        })
        |> Sovra.Repo.insert()

      metadata = OID4VCI.build_metadata(workspace, [schema])

      assert [display] = metadata["display"]
      assert display["name"] == "Branded"
      assert display["logo"] == %{"uri" => "https://branded.test/logo.png"}
      assert display["url"] == "https://branded.test"

      # Per-credential display also carries org branding (credential designs).
      cred_config = metadata["credential_configurations_supported"]["BrandedCredential"]
      assert [cred_display] = cred_config["credential_metadata"]["display"]
      assert cred_display["name"] == "Branded Credential"
      assert cred_display["logo"] == %{"uri" => "https://branded.test/logo.png"}
      assert cred_display["url"] == "https://branded.test"
    end

    test "omits logo/url when absent on organization" do
      owner =
        %Sovra.Accounts.User{}
        |> Sovra.Accounts.User.admin_changeset(%{
          email: "owner-#{System.unique_integer([:positive])}@example.com",
          password: "a-very-strong-password-123"
        })
        |> Sovra.Repo.insert!()

      {:ok, %{organization: org}} =
        Organizations.create_organization(owner.id, %{name: "Nude"})

      {:ok, workspace} =
        Sovra.Repo.insert(%Workspace{
          name: "Ignored",
          eoa_address: "0x" <> String.duplicate("ef", 20),
          eoa_key_id: "ek-#{System.unique_integer([:positive])}",
          signing_key_id: "sk-#{System.unique_integer([:positive])}",
          signing_public_key_x: <<1::256>>,
          signing_public_key_y: <<2::256>>,
          did:
            "did:sovra:0x#{Base.encode16(<<System.unique_integer([:positive])::256>>, case: :lower)}",
          organization_id: org.id,
          status_index_secret_key_id: "stub-#{System.unique_integer([:positive])}"
        })

      {:ok, schema} =
        Sovra.Issuer.CredentialSchema.create_changeset(%{
          schema_id: "nude-schema-#{System.unique_integer([:positive])}",
          issuer_id: workspace.id,
          credential_type: "NudeCredential",
          name: "Nude Credential",
          claims: [%{"key" => "name", "type" => "string", "required" => true}],
          validity_period: "1y"
        })
        |> Sovra.Repo.insert()

      metadata = OID4VCI.build_metadata(workspace, [schema])

      assert [display] = metadata["display"]
      assert display["name"] == "Nude"
      refute Map.has_key?(display, "logo")
      refute Map.has_key?(display, "url")

      # Per-credential display collapses to name-only when the org has no branding.
      cred_config = metadata["credential_configurations_supported"]["NudeCredential"]
      assert [cred_display] = cred_config["credential_metadata"]["display"]
      assert cred_display == %{"name" => "Nude Credential"}
    end
  end

  describe "build_metadata/3 claims description" do
    defp schema_with_claims(workspace, claims) do
      %Sovra.Issuer.CredentialSchema{
        id: Ecto.UUID.generate(),
        schema_id: "claims-schema",
        issuer_id: workspace.id,
        credential_type: "ClaimsCredential",
        name: "Claims Credential",
        claims: claims,
        validity_period: "1y",
        version: 1
      }
    end

    defp claims_of(workspace, claims) do
      metadata = OID4VCI.build_metadata(workspace, [schema_with_claims(workspace, claims)])

      metadata["credential_configurations_supported"]["ClaimsCredential"]["credential_metadata"][
        "claims"
      ]
    end

    test "publishes the issuer's label as a claim display entry" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      claims =
        claims_of(workspace, [
          %{"key" => "fullName", "label" => "Full name", "type" => "string", "required" => true}
        ])

      assert claims == [
               %{
                 "path" => ["fullName"],
                 "mandatory" => true,
                 "display" => [%{"name" => "Full name", "locale" => "en-US"}]
               }
             ]
    end

    test "keeps the schema's claim order" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      claims =
        claims_of(workspace, [
          %{"key" => "b", "label" => "Bee"},
          %{"key" => "a", "label" => "Ay"}
        ])

      assert Enum.map(claims, & &1["path"]) == [["b"], ["a"]]
    end

    test "describes an unlabelled claim without a display, leaving the wallet to derive one" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      assert [claim] = claims_of(workspace, [%{"key" => "age", "type" => "integer"}])
      assert claim == %{"path" => ["age"]}
    end

    test "treats a blank label as no label" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      assert [claim] = claims_of(workspace, [%{"key" => "age", "label" => "   "}])
      refute Map.has_key?(claim, "display")
    end

    test "trims surrounding whitespace off the label" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      assert [claim] = claims_of(workspace, [%{"key" => "age", "label" => "  Age  "}])
      assert claim["display"] == [%{"name" => "Age", "locale" => "en-US"}]
    end

    test "omits mandatory unless the claim is required" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      assert [optional, required] =
               claims_of(workspace, [
                 %{"key" => "a", "required" => false},
                 %{"key" => "b", "required" => true}
               ])

      refute Map.has_key?(optional, "mandatory")
      assert required["mandatory"] == true
    end

    test "publishes contentMediaType for an attachment, and for nothing else" do
      # A label hint, so a wallet can say "PDF document" before it has parsed
      # anything. Never a contract: the wallet decides a value is a document by
      # looking at the value, because a credential can reach it through paths
      # that carry no issuer metadata at all.
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      assert [scan, name] =
               claims_of(workspace, [
                 %{"key" => "licence_scan", "type" => "attachment", "disclosable" => true},
                 %{"key" => "family_name", "type" => "string"}
               ])

      assert scan["contentMediaType"] == "application/pdf"
      refute Map.has_key?(name, "contentMediaType")
    end

    test "skips claims with no usable key rather than emitting an empty path" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      claims = claims_of(workspace, [%{"key" => ""}, %{"type" => "string"}, %{"key" => "ok"}])

      assert claims == [%{"path" => ["ok"]}]
    end

    test "omits claims entirely when the schema declares none" do
      workspace = build_workspace(%{id: Ecto.UUID.generate()})

      metadata = OID4VCI.build_metadata(workspace, [schema_with_claims(workspace, [])])
      config = metadata["credential_configurations_supported"]["ClaimsCredential"]

      refute Map.has_key?(config["credential_metadata"], "claims")
    end
  end
end
