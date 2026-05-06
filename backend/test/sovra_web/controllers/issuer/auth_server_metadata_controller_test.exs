defmodule SovraWeb.Issuer.AuthServerMetadataControllerTest do
  use SovraWeb.ConnCase, async: false

  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  defp create_workspace do
    {:ok, account} =
      IssuerAccount.admin_changeset(%{
        email: "user-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Sovra.Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    did =
      "did:sovra:0x#{Base.encode16(<<System.unique_integer([:positive])::256>>, case: :lower)}"

    {:ok, workspace} =
      Sovra.Repo.insert(%Workspace{
        name: "Acme",
        eoa_address: "0x" <> String.duplicate("ab", 20),
        eoa_key_id: "ek-#{System.unique_integer([:positive])}",
        signing_key_id: "sk-#{System.unique_integer([:positive])}",
        signing_public_key_x: <<1::256>>,
        signing_public_key_y: <<2::256>>,
        did: did,
        organization_id: org.id
      })

    workspace
  end

  describe "GET /.well-known/oauth-authorization-server/:workspace_did" do
    test "returns AS metadata scoped to the workspace DID", %{conn: conn} do
      workspace = create_workspace()

      base_url = Sovra.Issuer.ClaimUtils.base_url()
      resp = conn |> get("/.well-known/oauth-authorization-server/#{workspace.did}")

      assert json = json_response(resp, 200)
      assert json["issuer"] == "#{base_url}/#{workspace.did}"
      assert json["token_endpoint"] == "#{base_url}/api/v1/issuer/token"

      assert json["grant_types_supported"] == [
               "urn:ietf:params:oauth:grant-type:pre-authorized_code"
             ]

      assert json["pre-authorized_grant_anonymous_access_supported"] == true
    end

    test "404 when the workspace DID is unknown", %{conn: conn} do
      resp = conn |> get("/.well-known/oauth-authorization-server/did:sovra:nonexistent")

      assert %{"error" => "issuer_not_found"} = json_response(resp, 404)
    end

    test "lookup is exact — partial DID does not match an existing workspace", %{conn: conn} do
      workspace = create_workspace()
      truncated = String.slice(workspace.did, 0..-2//1)

      resp = conn |> get("/.well-known/oauth-authorization-server/#{truncated}")

      assert json_response(resp, 404)
    end
  end
end
