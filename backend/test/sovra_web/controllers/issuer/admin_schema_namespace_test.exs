defmodule SovraWeb.Issuer.AdminSchemaNamespaceTest do
  @moduledoc """
  What a schema response has to carry about an mdoc, and why.

  `doc_type` and `namespace` are derived, never stored, so a response that
  forgets one is indistinguishable from a schema that has none — and the
  dashboard reads them to build a verification's DCQL query: the docType goes
  in `meta.doctype_value` and the namespace is the first segment of every
  claim path. A list response missing the namespace left the verification
  wizard unable to ask for a credential its own workspace issues.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Auth.UserSession
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces

  defp setup_issuer do
    {:ok, owner} =
      %{
        email: "u-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123",
        full_name: "Test Operator"
      }
      |> User.registration_changeset()
      |> Sovra.Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)

    %{owner: owner, workspace: provision_workspace(ws)}
  end

  defp authed(conn, user, workspace_id) do
    {:ok, token} = UserSession.create(user.id, workspace_id, user.is_admin)
    put_req_header(conn, "authorization", "Bearer #{token}")
  end

  defp create_mdoc_schema(conn, owner, ws) do
    conn
    |> authed(owner, ws.id)
    |> post("/dashboard/issuer/schemas", %{
      schema_id: "membership_card",
      credential_type: "MembershipCard",
      name: "Membership Card",
      format: "mso_mdoc",
      claims: [%{key: "full_name", type: "string", required: true}],
      validity_period: "1y"
    })
    |> json_response(201)
  end

  describe "an mdoc schema's docType and namespace" do
    test "the list carries both, not just the docType", %{conn: conn} do
      %{owner: owner, workspace: ws} = setup_issuer()
      created = create_mdoc_schema(conn, owner, ws)

      [listed] =
        conn
        |> authed(owner, ws.id)
        |> get("/dashboard/issuer/schemas")
        |> json_response(200)
        |> Map.fetch!("schemas")

      # A generated schema names neither, so both derive from the workspace
      # address and are equal — which is exactly why an absent namespace went
      # unnoticed: everything that already had the docType appeared to work.
      assert listed["doc_type"] =~ ~r/^io\.sovra\.0x[0-9a-f]{40}\.membership_card\.1$/
      assert listed["namespace"] == listed["doc_type"]
      assert listed["doc_type"] == created["doc_type"]
      assert listed["namespace"] == created["namespace"]
    end

    test "a revision carries both", %{conn: conn} do
      %{owner: owner, workspace: ws} = setup_issuer()
      created = create_mdoc_schema(conn, owner, ws)

      revised =
        conn
        |> authed(owner, ws.id)
        |> put("/dashboard/issuer/schemas/membership_card", %{
          base_version: 1,
          name: "Membership Card",
          claims: [
            %{key: "full_name", type: "string", required: true},
            %{key: "member_since", type: "string", required: false}
          ],
          validity_period: "1y"
        })
        |> json_response(201)

      # The format is fixed at creation, so a revision cannot change either
      # string — and must not drop them.
      assert revised["doc_type"] == created["doc_type"]
      assert revised["namespace"] == created["namespace"]
    end

    test "an sd-jwt schema has neither", %{conn: conn} do
      %{owner: owner, workspace: ws} = setup_issuer()

      conn
      |> authed(owner, ws.id)
      |> post("/dashboard/issuer/schemas", %{
        schema_id: "loyalty",
        credential_type: "Loyalty",
        name: "Loyalty",
        format: "vc+sd-jwt",
        claims: [%{key: "full_name", type: "string", required: true}],
        validity_period: "1y"
      })
      |> json_response(201)

      [listed] =
        conn
        |> authed(owner, ws.id)
        |> get("/dashboard/issuer/schemas")
        |> json_response(200)
        |> Map.fetch!("schemas")

      assert listed["doc_type"] == nil
      assert listed["namespace"] == nil
    end
  end
end
