defmodule Sovra.Mdl do
  @moduledoc """
  Issuing real mDLs: admitted trust anchors, and a workspace's document signer.

  ## The flow this context implements

  1. A platform admin admits an issuing authority's IACA root
     (`admit_issuing_authority/2`). That is the trust decision — see
     `Sovra.Mdl.IssuingAuthority` for why it cannot come from the certificate.
  2. A workspace generates a dedicated document signer key in KMS
     (`create_signing_key/1`) and exports a certification request for it
     (`certification_request/2`).
  3. The operator takes that request to their authority and comes back with a
     Document Signer Certificate, which they register
     (`register_document_signer/3`).

  Steps 2 and 3 are separated by however long the authority takes, which is why
  a workspace is allowed to hold a signing key with no certificate yet.

  ## Why the key is a separate one

  A workspace already has `signing_key_id` for SD-JWT. ISO expects a document
  signer to rotate on its own schedule — Annex B caps its certificate at 457
  days — and reusing the SD-JWT key would tie a format that needs no
  certificate to a certificate's lifecycle.
  """

  import Ecto.Query

  alias Sovra.Crypto.Key
  alias Sovra.Mdl.IssuingAuthority
  alias Sovra.Repo
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace
  alias Sovra.X509.Certificate
  alias Sovra.X509.Csr

  # ── Trust anchors ───────────────────────────────────────

  @doc """
  Admit an IACA root, after checking it against ISO 18013-5 Annex B.

  `admitted_by_user_id` is recorded rather than merely authorized against: a
  trust anchor is the kind of decision someone should be able to be asked
  about later.
  """
  @spec admit_issuing_authority(String.t(), Ecto.UUID.t() | nil) ::
          {:ok, IssuingAuthority.t()} | {:error, term()}
  def admit_issuing_authority(pem, admitted_by_user_id) when is_binary(pem) do
    with {:ok, certificate} <- Certificate.parse(pem),
         :ok <- Certificate.validate_iaca(certificate) do
      %{
        certificate: pem,
        subject_country: certificate.subject.country,
        subject_state: certificate.subject.state,
        subject_common_name: certificate.subject.common_name,
        not_before: DateTime.truncate(certificate.not_before, :second),
        not_after: DateTime.truncate(certificate.not_after, :second),
        fingerprint: fingerprint(certificate),
        admitted_at: DateTime.utc_now() |> DateTime.truncate(:second),
        admitted_by_user_id: admitted_by_user_id
      }
      |> IssuingAuthority.admit_changeset()
      |> Repo.insert()
    end
  end

  @doc "Every admitted root, newest first."
  @spec list_issuing_authorities() :: [IssuingAuthority.t()]
  def list_issuing_authorities do
    Repo.all(from a in IssuingAuthority, order_by: [desc: a.admitted_at])
  end

  @spec get_issuing_authority(Ecto.UUID.t()) ::
          {:ok, IssuingAuthority.t()} | {:error, :issuing_authority_not_found}
  def get_issuing_authority(id) do
    case Repo.get(IssuingAuthority, id) do
      nil -> {:error, :issuing_authority_not_found}
      authority -> {:ok, authority}
    end
  end

  @doc """
  Withdraw a root.

  Refused while any workspace still has a signer chaining to it — the
  alternative is a workspace that keeps issuing credentials no verifier of ours
  will accept, which surfaces as an unexplained `unknown_issuer` rather than as
  the withdrawal it actually is.
  """
  @spec withdraw_issuing_authority(Ecto.UUID.t()) :: :ok | {:error, term()}
  def withdraw_issuing_authority(id) do
    with {:ok, authority} <- get_issuing_authority(id) do
      case Repo.aggregate(
             from(w in Workspace, where: w.mdl_issuing_authority_id == ^authority.id),
             :count
           ) do
        0 ->
          {:ok, _} = Repo.delete(authority)
          :ok

        count ->
          {:error, {:issuing_authority_in_use, count}}
      end
    end
  end

  # ── The workspace's document signer ─────────────────────

  @doc """
  Generate the workspace's dedicated mDL document signer key in KMS.

  Idempotent: a workspace that already has one keeps it. Regenerating would
  orphan the certificate issued for the old key, and silently — the credential
  would still sign, and only a reader validating the chain would notice.
  """
  @spec create_signing_key(Ecto.UUID.t()) :: {:ok, Workspace.t()} | {:error, term()}
  def create_signing_key(workspace_id) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id) do
      if workspace.mdl_signing_key_id do
        {:ok, workspace}
      else
        with {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} <-
               Key.generate_key("workspace:#{workspace.id}:mdl-ds") do
          workspace
          |> Workspace.mdl_signing_key_changeset(%{
            mdl_signing_key_id: key_id,
            mdl_signing_public_key_x: x,
            mdl_signing_public_key_y: y
          })
          |> Repo.update()
        end
      end
    end
  end

  @doc """
  A PEM certification request for the workspace's document signer key.

  Nothing is persisted: the request is derived from the key and the subject
  every time, so an operator who loses it can simply ask again, and there is no
  stored copy to drift from the key it names.
  """
  @spec certification_request(Ecto.UUID.t(), Csr.subject()) ::
          {:ok, String.t()} | {:error, term()}
  def certification_request(workspace_id, subject) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id),
         {:ok, key_id, point} <- fetch_signing_key(workspace) do
      Csr.build(key_id, point, subject)
    end
  end

  @doc """
  Register the Document Signer Certificate an authority issued for this
  workspace.

  Every check that matters runs here, because this is the last moment anyone is
  looking. In particular the certificate must name *this workspace's* key: a
  valid chain certifying somebody else's key passes every profile rule and
  produces credentials whose `x5chain` asserts a binding the signature does not
  have.
  """
  @spec register_document_signer(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) ::
          {:ok, Workspace.t()} | {:error, term()}
  def register_document_signer(workspace_id, authority_id, pem) when is_binary(pem) do
    with {:ok, workspace} <- Workspaces.get_active_workspace(workspace_id),
         {:ok, _key_id, point} <- fetch_signing_key(workspace),
         {:ok, authority} <- get_issuing_authority(authority_id),
         {:ok, root} <- Certificate.parse(authority.certificate),
         {:ok, signer} <- Certificate.parse(pem),
         :ok <- Certificate.validate_document_signer(signer, root),
         :ok <- check_certifies(signer, point) do
      workspace
      |> Workspace.mdl_signer_changeset(%{
        mdl_signer_certificate: pem,
        mdl_issuing_authority_id: authority.id
      })
      |> Repo.update()
    end
  end

  @doc """
  The workspace whose document signer key is `{x, y}`.

  How an ISO-docType credential is attributed: the `x5chain` leaf certifies a
  key, and this is the only place that key appears on our side. Requires a
  registered certificate as well as the key, because a workspace that has
  generated a key but never come back with a certificate has not finished
  becoming an issuer — it can hold a key that no authority has vouched for.
  """
  @spec get_workspace_by_document_signer({binary(), binary()}) ::
          {:ok, Workspace.t()} | {:error, :document_signer_not_found}
  def get_workspace_by_document_signer({x, y}) when is_binary(x) and is_binary(y) do
    Workspace
    |> where(
      [w],
      w.mdl_signing_public_key_x == ^x and w.mdl_signing_public_key_y == ^y and
        not is_nil(w.mdl_signer_certificate)
    )
    |> Repo.one()
    |> case do
      nil -> {:error, :document_signer_not_found}
      workspace -> {:ok, workspace}
    end
  end

  @doc """
  Whether this workspace can issue credentials under an ISO docType.

  The two are the same question. A conformant docType carries no Sovra address,
  so the only way a verifier can find the issuer is the certificate chain — a
  workspace without one would issue credentials that resolve to nobody.
  """
  @spec can_issue_iso_doc_types?(Workspace.t()) :: boolean()
  def can_issue_iso_doc_types?(%Workspace{} = workspace),
    do: not is_nil(workspace.mdl_signer_certificate)

  # ── Internals ───────────────────────────────────────────

  defp fetch_signing_key(%Workspace{
         mdl_signing_key_id: key_id,
         mdl_signing_public_key_x: x,
         mdl_signing_public_key_y: y
       })
       when is_binary(key_id) and is_binary(x) and is_binary(y),
       do: {:ok, key_id, {x, y}}

  defp fetch_signing_key(_workspace), do: {:error, :mdl_signing_key_missing}

  defp check_certifies(signer, point) do
    if Certificate.certifies?(signer, point),
      do: :ok,
      else: {:error, {:dsc_profile, :certifies_another_key}}
  end

  defp fingerprint(%Certificate{der: der}), do: :crypto.hash(:sha256, der)
end
