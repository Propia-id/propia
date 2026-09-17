defmodule SovraWeb.Issuer.MdlControllerTest do
  @moduledoc """
  The mDL setup flow over HTTP: admitting a root, generating a key, exporting a
  certification request, registering the certificate that comes back.

  Two audiences, and the split between them is the point. Admitting a trust
  anchor is Sovra's decision and a workspace admin must not be able to make it;
  everything else is the workspace's and a platform admin has no special claim
  on it.
  """
  use SovraWeb.ConnCase, async: false

  alias Sovra.Accounts.User
  alias Sovra.Auth.UserSession
  alias Sovra.Mdl
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces
  alias SovraTest.MdlCertificates

  # `User.admin_changeset/2` always sets `is_admin: true` — it means "a platform
  # admin", not "an admin-console user" — so an ordinary issuer has to be
  # registered, or every test here would be run by somebody who can do anything.
  defp user(opts \\ []) do
    attrs = %{
      email: "u-#{System.unique_integer([:positive])}@example.com",
      password: "a-very-strong-password-123",
      full_name: "Test Operator"
    }

    changeset =
      if Keyword.get(opts, :platform_admin, false),
        do: User.admin_changeset(attrs),
        else: User.registration_changeset(attrs)

    {:ok, account} = Sovra.Repo.insert(changeset)
    account
  end

  defp workspace(owner) do
    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Sovra.Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "Acme"}, owner.id)
    provision_workspace(ws)
  end

  defp authed(conn, user, workspace_id) do
    {:ok, token} = UserSession.create(user.id, workspace_id, user.is_admin)
    put_req_header(conn, "authorization", "Bearer #{token}")
  end

  defp setup_issuer do
    owner = user()
    %{owner: owner, workspace: workspace(owner)}
  end

  describe "admitting a trust anchor" do
    test "a platform admin admits a conformant IACA root", %{conn: conn} do
      admin = user(platform_admin: true)
      ws = workspace(admin)
      iaca = MdlCertificates.iaca(country: "ES", common_name: "Spanish IACA")

      resp =
        conn
        |> authed(admin, ws.id)
        |> post("/dashboard/mdl/issuing-authorities", %{certificate: iaca.pem})
        |> json_response(201)

      assert resp["subject_country"] == "ES"
      assert resp["subject_common_name"] == "Spanish IACA"
      assert resp["fingerprint"] =~ ~r/^[0-9a-f]{64}$/
    end

    test "a workspace owner cannot", %{conn: conn} do
      # Which roots our verifiers trust is not a workspace's decision — an
      # issuer that could admit its own root could vouch for itself, and the
      # whole trust anchor table would mean nothing.
      %{owner: owner, workspace: ws} = setup_issuer()
      iaca = MdlCertificates.iaca()

      conn
      |> authed(owner, ws.id)
      |> post("/dashboard/mdl/issuing-authorities", %{certificate: iaca.pem})
      |> json_response(403)
    end

    test "a certificate that breaks the profile names the rule it broke", %{conn: conn} do
      # The operator is holding a certificate and has to know which field to go
      # back to their CA about. "invalid certificate" tells them nothing.
      admin = user(platform_admin: true)
      ws = workspace(admin)

      not_a_ca =
        MdlCertificates.iaca(basic_constraints: {:BasicConstraints, false, :asn1_NOVALUE})

      resp =
        conn
        |> authed(admin, ws.id)
        |> post("/dashboard/mdl/issuing-authorities", %{certificate: not_a_ca.pem})
        |> json_response(422)

      assert resp["error"] == "invalid_certificate"
      assert resp["reason"] == "iaca_profile.basic_constraints"
    end

    test "withdrawing is refused while a workspace still chains to it", %{conn: conn} do
      # The alternative is a workspace that keeps issuing credentials no
      # verifier of ours accepts, surfacing as an unexplained `unknown_issuer`
      # rather than as the withdrawal it actually is.
      admin = user(platform_admin: true)
      ws = workspace(admin)
      %{authority: authority} = MdlCertificates.provision_document_signer(ws)

      resp =
        conn
        |> authed(admin, ws.id)
        |> delete("/dashboard/mdl/issuing-authorities/#{authority.id}")
        |> json_response(409)

      assert resp["error"] == "issuing_authority_in_use"
      assert resp["workspace_count"] == 1
    end

    test "withdrawing an unused root succeeds", %{conn: conn} do
      admin = user(platform_admin: true)
      ws = workspace(admin)
      {:ok, authority} = Mdl.admit_issuing_authority(MdlCertificates.iaca().pem, admin.id)

      conn
      |> authed(admin, ws.id)
      |> delete("/dashboard/mdl/issuing-authorities/#{authority.id}")
      |> response(204)

      assert Mdl.list_issuing_authorities() == []
    end
  end

  describe "becoming an mDL issuer" do
    test "the whole flow: key, request, certificate", %{conn: conn} do
      %{owner: owner, workspace: ws} = setup_issuer()
      admin = user(platform_admin: true)
      iaca = MdlCertificates.iaca(country: "ES", common_name: "Spanish IACA")
      {:ok, authority} = Mdl.admit_issuing_authority(iaca.pem, admin.id)

      # Nothing yet.
      before = conn |> authed(owner, ws.id) |> get("/dashboard/issuer/mdl/signer")
      assert json_response(before, 200)["has_signing_key"] == false
      assert json_response(before, 200)["can_issue_iso_doc_types"] == false

      # A key, in KMS. The private half has no representation in any response.
      keyed =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/mdl/signing-key")
        |> json_response(201)

      assert keyed["has_signing_key"] == true
      assert keyed["can_issue_iso_doc_types"] == false

      # A certification request for it.
      request =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/mdl/certification-request", %{
          country: "ES",
          common_name: "Acme Document Signer"
        })
        |> json_response(200)

      assert request["certification_request"] =~ "BEGIN CERTIFICATE REQUEST"

      # The certificate the authority issues back, for the key the request
      # named — which is the check that actually matters.
      reloaded = Sovra.Repo.reload!(ws)

      signer =
        MdlCertificates.document_signer(
          iaca,
          {reloaded.mdl_signing_public_key_x, reloaded.mdl_signing_public_key_y}
        )

      registered =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/mdl/document-signer", %{
          issuing_authority_id: authority.id,
          certificate: signer.pem
        })
        |> json_response(201)

      assert registered["can_issue_iso_doc_types"] == true
      assert registered["certificate"] == signer.pem
    end

    test "a certificate for somebody else's key is refused", %{conn: conn} do
      # The one check here that is about correctness rather than conformance. A
      # valid chain certifying another key passes every profile rule and
      # produces credentials whose `x5chain` asserts a binding the signature
      # does not have.
      %{owner: owner, workspace: ws} = setup_issuer()
      admin = user(platform_admin: true)
      iaca = MdlCertificates.iaca()
      {:ok, authority} = Mdl.admit_issuing_authority(iaca.pem, admin.id)
      {:ok, _} = Mdl.create_signing_key(ws.id)

      {{x, y}, _private} = MdlCertificates.keypair_point()
      stranger = MdlCertificates.document_signer(iaca, {x, y})

      resp =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/mdl/document-signer", %{
          issuing_authority_id: authority.id,
          certificate: stranger.pem
        })
        |> json_response(422)

      assert resp["reason"] == "dsc_profile.certifies_another_key"
    end

    test "a certification request before a key exists is a conflict", %{conn: conn} do
      %{owner: owner, workspace: ws} = setup_issuer()

      resp =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/mdl/certification-request", %{
          country: "ES",
          common_name: "Acme"
        })
        |> json_response(409)

      assert resp["error"] == "mdl_signing_key_missing"
    end

    test "a subject with no country is refused", %{conn: conn} do
      # Annex B requires it, and the DSC's country has to match its root's — a
      # request without one produces a certificate no authority can issue.
      %{owner: owner, workspace: ws} = setup_issuer()
      {:ok, _} = Mdl.create_signing_key(ws.id)

      conn
      |> authed(owner, ws.id)
      |> post("/dashboard/issuer/mdl/certification-request", %{common_name: "Acme"})
      |> json_response(422)
    end

    test "generating a key twice keeps the first one", %{conn: conn} do
      # Regenerating would orphan the certificate issued for the old key, and
      # silently: the credential would still sign, and only a reader validating
      # the chain would notice.
      %{owner: owner, workspace: ws} = setup_issuer()

      conn |> authed(owner, ws.id) |> post("/dashboard/issuer/mdl/signing-key")
      first = Sovra.Repo.reload!(ws).mdl_signing_key_id

      conn |> authed(owner, ws.id) |> post("/dashboard/issuer/mdl/signing-key")
      assert Sovra.Repo.reload!(ws).mdl_signing_key_id == first
    end
  end

  describe "the ISO template" do
    test "is served so the console cannot drift from what the changeset accepts", %{conn: conn} do
      %{owner: owner, workspace: ws} = setup_issuer()

      resp =
        conn
        |> authed(owner, ws.id)
        |> get("/dashboard/issuer/mdl/template")
        |> json_response(200)

      assert resp["doc_type"] == "org.iso.18013.5.1.mDL"
      assert resp["namespace"] == "org.iso.18013.5.1"
      assert length(resp["mandatory_elements"]) == 11
      assert "portrait" in resp["mandatory_elements"]

      portrait = Enum.find(resp["claims"], &(&1["key"] == "portrait"))
      assert portrait["type"] == "bytes"
      assert portrait["required"]
    end

    test "a schema built from it is accepted", %{conn: conn} do
      # The claim this endpoint exists to make good on: what the console offers
      # is what schema creation takes.
      %{owner: owner, workspace: ws} = setup_issuer()
      %{workspace: ws} = MdlCertificates.provision_document_signer(ws)

      template =
        conn
        |> authed(owner, ws.id)
        |> get("/dashboard/issuer/mdl/template")
        |> json_response(200)

      created =
        conn
        |> authed(owner, ws.id)
        |> post("/dashboard/issuer/schemas", %{
          schema_id: "mdl",
          credential_type: "DrivingLicence",
          name: "Driving Licence",
          format: "mso_mdoc",
          doc_type: template["doc_type"],
          namespace: template["namespace"],
          claims: template["claims"],
          validity_period: "1y"
        })
        |> json_response(201)

      assert created["doc_type"] == "org.iso.18013.5.1.mDL"
      assert created["namespace"] == "org.iso.18013.5.1"
    end
  end
end
