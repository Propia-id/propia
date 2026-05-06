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
      assert [cred_display] = cred_config["display"]
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
      assert [cred_display] = cred_config["display"]
      assert cred_display == %{"name" => "Nude Credential"}
    end
  end
end
