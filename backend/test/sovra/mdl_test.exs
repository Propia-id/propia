defmodule Sovra.MdlTest do
  @moduledoc """
  The registration flow end to end: admit a root, generate a signer key, export
  a certification request, get it signed, register the result.

  The authority is simulated by `SovraTest.MdlCertificates`, which signs the
  request the same way a real one would — so what is under test is our half of
  a handshake, not a fixture written to match it.
  """
  use Sovra.DataCase, async: true

  alias Sovra.Mdl
  alias Sovra.Workspaces
  alias SovraTest.MdlCertificates, as: Mint

  defp active_workspace do
    %{workspace: workspace, owner: owner} = fixture_workspace()
    {:ok, workspace} = Workspaces.get_active_workspace(workspace.id)
    %{workspace: workspace, owner: owner}
  end

  defp with_signing_key do
    %{workspace: workspace, owner: owner} = active_workspace()
    {:ok, workspace} = Mdl.create_signing_key(workspace.id)
    %{workspace: workspace, owner: owner}
  end

  describe "admit_issuing_authority/2" do
    test "admits a conformant root and denormalises its subject" do
      %{owner: owner} = active_workspace()
      root = Mint.iaca(country: "ES", common_name: "Dirección General de Tráfico")

      assert {:ok, authority} = Mdl.admit_issuing_authority(root.pem, owner.id)
      assert authority.subject_country == "ES"
      assert authority.subject_common_name == "Dirección General de Tráfico"
      assert authority.admitted_by_user_id == owner.id
      assert authority.fingerprint == :crypto.hash(:sha256, root.der)
    end

    test "refuses a root that fails the Annex B profile" do
      not_a_ca = Mint.iaca(basic_constraints: {:BasicConstraints, false, :asn1_NOVALUE})

      assert {:error, {:iaca_profile, :basic_constraints}} =
               Mdl.admit_issuing_authority(not_a_ca.pem, nil)
    end

    test "recognises a re-uploaded root rather than admitting it twice" do
      # Two rows for one anchor would mean withdrawing one and still trusting
      # the other.
      root = Mint.iaca()
      assert {:ok, _} = Mdl.admit_issuing_authority(root.pem, nil)
      assert {:error, changeset} = Mdl.admit_issuing_authority(root.pem, nil)
      assert "this root is already admitted" in errors_on(changeset).fingerprint
    end
  end

  describe "create_signing_key/1" do
    test "gives the workspace a document signer key distinct from its SD-JWT key" do
      %{workspace: workspace} = active_workspace()

      assert {:ok, updated} = Mdl.create_signing_key(workspace.id)
      assert updated.mdl_signing_key_id
      assert byte_size(updated.mdl_signing_public_key_x) == 32
      assert updated.mdl_signing_key_id != updated.signing_key_id
    end

    test "is idempotent, because regenerating would orphan the certificate" do
      %{workspace: workspace} = active_workspace()
      {:ok, first} = Mdl.create_signing_key(workspace.id)
      {:ok, second} = Mdl.create_signing_key(workspace.id)

      assert first.mdl_signing_key_id == second.mdl_signing_key_id
    end

    test "refuses a workspace that is not active" do
      %{workspace: workspace} = active_workspace()

      {:ok, _} =
        workspace |> Sovra.Workspaces.Workspace.status_changeset("suspended") |> Repo.update()

      assert {:error, :workspace_inactive} = Mdl.create_signing_key(workspace.id)
    end
  end

  describe "certification_request/2" do
    test "requests a certificate for the workspace's own signer key" do
      %{workspace: workspace} = with_signing_key()

      assert {:ok, pem} =
               Mdl.certification_request(workspace.id,
                 country: "ES",
                 common_name: "Sovra DS 01"
               )

      [{:CertificationRequest, der, :not_encrypted}] = :public_key.pem_decode(pem)

      point = <<0x04>> <> workspace.mdl_signing_public_key_x <> workspace.mdl_signing_public_key_y
      assert :binary.match(der, point) != :nomatch
    end

    test "refuses before a signing key exists" do
      %{workspace: workspace} = active_workspace()

      assert {:error, :mdl_signing_key_missing} =
               Mdl.certification_request(workspace.id, country: "ES", common_name: "X")
    end
  end

  describe "register_document_signer/3" do
    setup do
      %{workspace: workspace} = with_signing_key()
      root = Mint.iaca(country: "ES", common_name: "Test IACA")
      {:ok, authority} = Mdl.admit_issuing_authority(root.pem, nil)

      point = {workspace.mdl_signing_public_key_x, workspace.mdl_signing_public_key_y}
      %{workspace: workspace, root: root, authority: authority, point: point}
    end

    test "registers a certificate the authority issued for this key", context do
      %{workspace: workspace, root: root, authority: authority, point: point} = context
      signer = Mint.document_signer(root, point, country: "ES")

      assert {:ok, updated} =
               Mdl.register_document_signer(workspace.id, authority.id, signer.pem)

      assert updated.mdl_signer_certificate == signer.pem
      assert updated.mdl_issuing_authority_id == authority.id
      assert Mdl.can_issue_iso_doc_types?(updated)
    end

    test "refuses a certificate for somebody else's key", context do
      %{workspace: workspace, root: root, authority: authority} = context
      {other_point, _private} = Mint.keypair_point()

      # A perfectly valid chain, correct in every profile respect, certifying a
      # key this workspace does not hold. Accepting it would produce credentials
      # whose x5chain asserts a binding the signature does not have.
      signer = Mint.document_signer(root, other_point, country: "ES")

      assert {:error, {:dsc_profile, :certifies_another_key}} =
               Mdl.register_document_signer(workspace.id, authority.id, signer.pem)
    end

    test "refuses a certificate chaining to a root we did not admit", context do
      %{workspace: workspace, authority: authority, point: point} = context
      stranger = Mint.iaca(country: "ES", common_name: "Unadmitted IACA")
      signer = Mint.document_signer(stranger, point, country: "ES")

      assert {:error, {:dsc_profile, {:chain, _}}} =
               Mdl.register_document_signer(workspace.id, authority.id, signer.pem)
    end

    test "refuses a certificate that breaks the Annex B profile", context do
      %{workspace: workspace, root: root, authority: authority, point: point} = context

      signer =
        Mint.document_signer(root, point,
          country: "ES",
          not_before: Mint.days_from_now(-1),
          not_after: Mint.days_from_now(900)
        )

      assert {:error, {:dsc_profile, :validity_too_long}} =
               Mdl.register_document_signer(workspace.id, authority.id, signer.pem)
    end

    test "a workspace with no signer cannot name its own docType", %{authority: _} do
      %{workspace: workspace} = active_workspace()
      refute Mdl.can_issue_iso_doc_types?(workspace)
    end
  end

  describe "withdraw_issuing_authority/1" do
    test "withdraws a root nothing depends on" do
      {:ok, authority} = Mdl.admit_issuing_authority(Mint.iaca().pem, nil)
      assert :ok = Mdl.withdraw_issuing_authority(authority.id)
      assert {:error, :issuing_authority_not_found} = Mdl.get_issuing_authority(authority.id)
    end

    test "refuses while a workspace still chains to it" do
      %{workspace: workspace} = with_signing_key()
      root = Mint.iaca(country: "ES")
      {:ok, authority} = Mdl.admit_issuing_authority(root.pem, nil)
      point = {workspace.mdl_signing_public_key_x, workspace.mdl_signing_public_key_y}
      signer = Mint.document_signer(root, point, country: "ES")
      {:ok, _} = Mdl.register_document_signer(workspace.id, authority.id, signer.pem)

      # Withdrawing here would leave the workspace issuing credentials our own
      # verifiers reject, reported as `unknown_issuer` rather than as this.
      assert {:error, {:issuing_authority_in_use, 1}} =
               Mdl.withdraw_issuing_authority(authority.id)
    end
  end
end
