defmodule SovraWeb.Issuer.MdlController do
  @moduledoc """
  The mDL issuer setup flow, and the trust anchors it runs against.

  Two audiences on one controller, separated by the router rather than by
  anything here:

    * a **platform admin** admits and withdraws IACA roots. That is the trust
      decision — see `Sovra.Mdl.IssuingAuthority` for why it cannot come from
      the certificate — and it is not a workspace's to make.
    * a **workspace admin** generates a document signer key, exports a
      certification request for it, and registers the certificate their
      authority issues back.

  Nothing here decides anything. Every rule lives in `Sovra.Mdl` and
  `Sovra.X509.Certificate`, because the same rules have to hold for a caller
  that is not this controller — a profile check living in a controller is one a
  background job silently skips.
  """

  use SovraWeb, :controller

  alias Sovra.Mdl
  alias Sovra.Mdl.Template
  alias Sovra.Workspaces

  # ── Trust anchors (platform admin) ──────────────────────

  def admit_issuing_authority(conn, params) do
    with {:ok, pem} <- fetch_certificate(params),
         {:ok, authority} <- Mdl.admit_issuing_authority(pem, conn.assigns.current_user.user_id) do
      conn |> put_status(201) |> json(issuing_authority(authority))
    else
      error -> respond_error(conn, error)
    end
  end

  def list_issuing_authorities(conn, _params) do
    json(conn, %{
      issuing_authorities: Enum.map(Mdl.list_issuing_authorities(), &issuing_authority/1)
    })
  end

  def withdraw_issuing_authority(conn, %{"id" => id}) do
    case Mdl.withdraw_issuing_authority(id) do
      :ok -> send_resp(conn, 204, "")
      error -> respond_error(conn, error)
    end
  end

  # ── A workspace's document signer ───────────────────────

  @doc """
  Where the workspace is in the flow.

  One endpoint rather than three, because the console renders one screen and
  the interesting thing is always *which step is next*: no key, a key with no
  certificate, or done.
  """
  def signer(conn, _params) do
    case Workspaces.get_active_workspace(workspace_id(conn)) do
      {:ok, workspace} -> json(conn, signer_state(workspace))
      error -> respond_error(conn, error)
    end
  end

  def create_signing_key(conn, _params) do
    case Mdl.create_signing_key(workspace_id(conn)) do
      {:ok, workspace} -> conn |> put_status(201) |> json(signer_state(workspace))
      error -> respond_error(conn, error)
    end
  end

  @doc """
  The PKCS#10 certification request, as PEM.

  In a JSON body rather than as a file download: the console shows it for
  copying as often as it saves it. Nothing is stored, so an operator who loses
  it asks again and the request is rebuilt from the key — there is no stored
  copy to drift from the key it names.
  """
  def certification_request(conn, params) do
    with {:ok, subject} <- fetch_subject(params),
         {:ok, pem} <- Mdl.certification_request(workspace_id(conn), subject) do
      json(conn, %{certification_request: pem})
    else
      error -> respond_error(conn, error)
    end
  end

  def register_document_signer(conn, params) do
    with {:ok, pem} <- fetch_certificate(params),
         {:ok, authority_id} <- fetch_authority_id(params),
         {:ok, workspace} <- Mdl.register_document_signer(workspace_id(conn), authority_id, pem) do
      conn |> put_status(201) |> json(signer_state(workspace))
    else
      error -> respond_error(conn, error)
    end
  end

  # ── The ISO template ────────────────────────────────────

  @doc """
  The ISO mDL element set, for seeding a schema in the console.

  Served rather than hardcoded in the frontend so the console cannot drift from
  what `Sovra.Issuer.CredentialSchema` accepts. The namespace is a closed set,
  and a builder offering an element the changeset rejects is a dead end
  reachable by clicking the obvious button.
  """
  def template(conn, _params) do
    json(conn, %{
      doc_type: Template.doc_type(),
      namespace: Template.namespace(),
      mandatory_elements: Template.mandatory_elements(),
      claims: Template.claim_definitions()
    })
  end

  # ── Rendering ───────────────────────────────────────────

  defp issuing_authority(authority) do
    %{
      id: authority.id,
      subject_country: authority.subject_country,
      subject_state: authority.subject_state,
      subject_common_name: authority.subject_common_name,
      not_before: authority.not_before,
      not_after: authority.not_after,
      fingerprint: Base.encode16(authority.fingerprint, case: :lower),
      admitted_at: authority.admitted_at
    }
  end

  # The certificate is returned because an operator checking what is installed
  # has nothing else to compare against what their CA sent. The *key* never
  # appears — it is in KMS and has no representation here.
  defp signer_state(workspace) do
    %{
      has_signing_key: not is_nil(workspace.mdl_signing_key_id),
      certificate: workspace.mdl_signer_certificate,
      issuing_authority_id: workspace.mdl_issuing_authority_id,
      can_issue_iso_doc_types: Mdl.can_issue_iso_doc_types?(workspace)
    }
  end

  # ── Errors ──────────────────────────────────────────────

  # A profile failure names the rule that failed, because the operator is
  # holding a certificate and needs to know which field to go back to their CA
  # about. `{:dsc_profile, :validity_too_long}` renders as
  # `dsc_profile.validity_too_long`; "invalid certificate" would tell them
  # nothing they can act on.
  defp respond_error(conn, {:error, {profile, reason}})
       when profile in [:iaca_profile, :dsc_profile, :certificate] do
    conn
    |> put_status(422)
    |> json(%{error: "invalid_certificate", reason: "#{profile}.#{detail(reason)}"})
  end

  defp respond_error(conn, {:error, {:validation, field, message}}) do
    conn |> put_status(422) |> json(%{error: "validation_error", details: %{field => [message]}})
  end

  defp respond_error(conn, {:error, %Ecto.Changeset{} = changeset}) do
    conn
    |> put_status(422)
    |> json(%{error: "validation_error", details: changeset_errors(changeset)})
  end

  # Refusing to strand workspaces that still chain to this root — see
  # `Sovra.Mdl.withdraw_issuing_authority/1`. A conflict, not a validation
  # failure: nothing about the request is wrong.
  defp respond_error(conn, {:error, {:issuing_authority_in_use, count}}) do
    conn
    |> put_status(409)
    |> json(%{error: "issuing_authority_in_use", workspace_count: count})
  end

  defp respond_error(conn, {:error, :issuing_authority_not_found}),
    do: conn |> put_status(404) |> json(%{error: "issuing_authority_not_found"})

  defp respond_error(conn, {:error, :mdl_signing_key_missing}),
    do: conn |> put_status(409) |> json(%{error: "mdl_signing_key_missing"})

  # `Sovra.X509.Csr` rejects a subject Annex B would not accept — a missing
  # country, or one that is not ISO 3166-1 alpha-2. The operator typed it, so
  # they are told which field.
  defp respond_error(conn, {:error, {reason, field}})
       when reason in [:missing_subject_field, :invalid_subject] do
    conn
    |> put_status(422)
    |> json(%{error: "validation_error", details: %{field => [to_string(reason)]}})
  end

  defp respond_error(conn, {:error, reason})
       when reason in [:workspace_inactive, :organization_inactive, :workspace_not_found],
       do: conn |> put_status(409) |> json(%{error: to_string(reason)})

  defp respond_error(conn, _error),
    do: conn |> put_status(500) |> json(%{error: "internal_error"})

  defp detail({:chain, reason}), do: "chain.#{detail(reason)}"
  defp detail(reason) when is_atom(reason), do: to_string(reason)
  defp detail(reason), do: inspect(reason)

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  # ── Params ──────────────────────────────────────────────

  defp workspace_id(conn), do: conn.assigns.current_user.workspace_id

  defp fetch_certificate(%{"certificate" => pem}) when is_binary(pem) and pem != "",
    do: {:ok, pem}

  defp fetch_certificate(_params), do: {:error, {:validation, :certificate, "is required"}}

  defp fetch_authority_id(%{"issuing_authority_id" => id}) when is_binary(id) and id != "",
    do: {:ok, id}

  defp fetch_authority_id(_params),
    do: {:error, {:validation, :issuing_authority_id, "is required"}}

  # `Sovra.X509.Csr` re-checks country and common name rather than trusting
  # this, because it is also reachable from a mix task and from a test. Blanks
  # are dropped so an empty optional field is absent rather than an empty RDN.
  defp fetch_subject(params) do
    {:ok,
     [
       country: params["country"],
       common_name: params["common_name"],
       state: params["state"],
       organization: params["organization"]
     ]
     |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)}
  end
end
