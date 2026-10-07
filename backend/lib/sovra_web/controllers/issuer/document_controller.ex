defmodule SovraWeb.Issuer.DocumentController do
  @moduledoc """
  Issues signed documents. One call to validate, sign and store, with no offer
  and no wallet in between.
  """

  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Documents
  alias Sovra.Documents.Attestation
  alias Sovra.Issuer.ClaimUtils

  tags(["Signed Documents"])

  @document %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      status: %OpenApiSpex.Schema{
        type: :string,
        enum: ["signed", "anchored", "failed", "revoked"],
        description:
          "`anchored` is the only shippable state. A new document is `signed` while its " <>
            "anchoring transaction is sent in the background, and moves to `anchored`, or " <>
            "to `failed` if the transaction never lands, in which case a verifier rejects " <>
            "it. Each move is announced by a `document.status-changed` webhook."
      },
      visibility: %OpenApiSpex.Schema{
        type: :string,
        enum: ["public", "private"],
        description:
          "`public` means holding the link is enough to read the document. `private` also " <>
            "requires a session on both public endpoints, so nobody sees the page as the " <>
            "issuer laid it out without an account."
      },
      credential: %OpenApiSpex.Schema{
        type: :string,
        description: "The signed document, an SD-JWT VC with no disclosures: `<jwt>~`."
      },
      claims: %OpenApiSpex.Schema{type: :object},
      digest: %OpenApiSpex.Schema{
        type: :string,
        description:
          "Hex sha256 of the JWS signing input. The key the signature is anchored under."
      },
      tx_hash: %OpenApiSpex.Schema{type: :string, nullable: true},
      signed_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
      anchored_at: %OpenApiSpex.Schema{type: :string, format: :"date-time", nullable: true},
      revoked_at: %OpenApiSpex.Schema{type: :string, format: :"date-time", nullable: true},
      issuer: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          did: %OpenApiSpex.Schema{type: :string},
          name: %OpenApiSpex.Schema{type: :string},
          address: %OpenApiSpex.Schema{type: :string}
        }
      },
      schema: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          id: %OpenApiSpex.Schema{type: :string, format: :uuid},
          schema_id: %OpenApiSpex.Schema{type: :string},
          name: %OpenApiSpex.Schema{type: :string},
          credential_type: %OpenApiSpex.Schema{type: :string},
          claims: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :object}},
          version: %OpenApiSpex.Schema{type: :integer}
        }
      }
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      error: %OpenApiSpex.Schema{type: :string},
      details: %OpenApiSpex.Schema{type: :object, nullable: true}
    }
  }

  operation(:create,
    summary: "Issue a signed document",
    description:
      "Validates the claims, signs them and stores the document, which comes back " <>
        "`signed`. The signature is then anchored on-chain in the background: the " <>
        "document moves to `anchored` (or `failed`) and a `document.status-changed` " <>
        "webhook carries the new `status`. The schema must be of kind `document`. Claims " <>
        "the schema does not declare are dropped before signing.",
    request_body:
      {"Document params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:schema_id],
         properties: %{
           schema_id: %OpenApiSpex.Schema{
             type: :string,
             description: "The schema's own id, not its UUID. Its latest version is used."
           },
           claims: %OpenApiSpex.Schema{
             type: :object,
             description: "Claim values keyed by the schema's claim keys."
           },
           visibility: %OpenApiSpex.Schema{
             type: :string,
             enum: ["public", "private"],
             default: "public",
             description:
               "`private` requires a session to read the document from either public " <>
                 "endpoint. It gates those endpoints only: a credential already handed out " <>
                 "stays verifiable against the chain by anyone holding it."
           },
           valid_until: %OpenApiSpex.Schema{
             type: :string,
             format: :"date-time",
             description:
               "Optional absolute expiry for this document, overriding the schema's " <>
                 "`validity_period`. Must be in the future. Omit the field to derive " <>
                 "expiry from the schema as before; `null` is rejected."
           }
         }
       }},
    responses: %{
      201 => {"Document issued", "application/json", @document},
      404 => {"Schema or workspace not found", "application/json", @error},
      409 =>
        {"Workspace not provisioned, or the schema's credential type is not registered " <>
           "on-chain yet (`schema_registration_pending`) or could not be " <>
           "(`schema_registration_failed`)", "application/json", @error},
      422 =>
        {"Wrong schema kind, missing required claims, unknown visibility, or validation error",
         "application/json", @error},
      503 =>
        {"No signature registry configured, so nothing can be anchored and issuance is refused",
         "application/json", @error}
    }
  )

  def create(conn, params) do
    workspace_id = conn.assigns.current_workspace_id

    # Absent and null are kept distinct: omitting the key asks for the schema's
    # validity period, while an explicit null is a caller describing an expiry
    # it could not compute. Only `Map.fetch/2` can tell the two apart.
    case Map.fetch(params, "valid_until") do
      :error ->
        issue(conn, workspace_id, params, nil)

      {:ok, value} ->
        case ClaimUtils.parse_valid_until(value) do
          {:ok, valid_until} -> issue(conn, workspace_id, params, valid_until)
          {:error, reason} -> handle_error(conn, {:error, {:invalid_valid_until, reason}})
        end
    end
  end

  defp issue(conn, workspace_id, params, valid_until) do
    opts = [visibility: params["visibility"], valid_until: valid_until]

    case Documents.issue(workspace_id, params["schema_id"], params["claims"] || %{}, opts) do
      {:ok, document} ->
        conn |> put_status(201) |> json(render_document(document))

      error ->
        handle_error(conn, error)
    end
  end

  operation(:index,
    summary: "List issued documents",
    description: "Every signed document in the workspace, newest first.",
    responses: %{
      200 =>
        {"Document list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             documents: %OpenApiSpex.Schema{type: :array, items: @document}
           }
         }}
    }
  )

  def index(conn, _params) do
    documents = Documents.list(conn.assigns.current_workspace_id)
    json(conn, %{documents: Enum.map(documents, &render_document/1)})
  end

  operation(:update_visibility,
    summary: "Change who may read a document",
    description:
      "Going private closes the link, not the copies: a credential already handed out stays " <>
        "readable and verifiable by whoever holds it. Not covered by the signature, so this " <>
        "invalidates nothing.",
    parameters: [
      id: [in: :path, type: :string, description: "Document UUID", required: true],
      visibility: [
        in: :path,
        type: %OpenApiSpex.Schema{type: :string, enum: ["public", "private"]},
        description: "The new visibility",
        required: true
      ]
    ],
    responses: %{
      200 => {"Document updated", "application/json", @document},
      404 => {"No document with that id in this workspace", "application/json", @error},
      422 => {"Unknown visibility", "application/json", @error}
    }
  )

  def update_visibility(conn, %{"id" => id, "visibility" => visibility}) do
    case Documents.set_visibility(conn.assigns.current_workspace_id, id, visibility) do
      {:ok, document} -> json(conn, render_document(document))
      error -> handle_error(conn, error)
    end
  end

  defp render_document(document) do
    %{
      id: document.id,
      status: document.status,
      visibility: document.visibility,
      credential: document.credential,
      claims: Attestation.claims(document.credential, document.schema),
      digest: Documents.hex(document.digest),
      tx_hash: document.tx_hash,
      signed_at: DateTime.to_iso8601(document.signed_at),
      issuer: %{
        did: document.workspace.did,
        name: document.workspace.name,
        address: document.workspace.eoa_address
      },
      anchored_at: document.anchored_at && DateTime.to_iso8601(document.anchored_at),
      revoked_at: document.revoked_at && DateTime.to_iso8601(document.revoked_at),
      schema: %{
        id: document.schema.id,
        schema_id: document.schema.schema_id,
        name: document.schema.name,
        credential_type: document.schema.credential_type,
        claims: document.schema.claims,
        version: document.schema.version
      }
    }
  end

  defp handle_error(conn, {:error, :document_not_found}),
    do: conn |> put_status(404) |> json(%{error: "document_not_found"})

  defp handle_error(conn, {:error, :schema_not_found}),
    do: conn |> put_status(404) |> json(%{error: "schema_not_found"})

  defp handle_error(conn, {:error, :workspace_not_found}),
    do: conn |> put_status(404) |> json(%{error: "workspace_not_found"})

  defp handle_error(conn, {:error, :workspace_not_provisioned}),
    do: conn |> put_status(409) |> json(%{error: "workspace_not_provisioned"})

  defp handle_error(conn, {:error, :schema_registration_pending}),
    do:
      conn
      |> put_status(409)
      |> json(%{
        error: "schema_registration_pending",
        details:
          "the schema's credential type is still being registered on-chain; retry in a few seconds"
      })

  defp handle_error(conn, {:error, :schema_registration_failed}),
    do:
      conn
      |> put_status(409)
      |> json(%{
        error: "schema_registration_failed",
        details:
          "the schema's credential type could not be registered on-chain, so nothing can be issued from it"
      })

  # The caller did nothing wrong: this server cannot anchor, so it will not sign.
  defp handle_error(conn, {:error, :chain_not_configured}),
    do:
      conn
      |> put_status(503)
      |> json(%{
        error: "chain_not_configured",
        details: "no signature registry is configured, so a document cannot be anchored"
      })

  defp handle_error(conn, {:error, {:wrong_schema_kind, kind}}) do
    conn
    |> put_status(422)
    |> json(%{
      error: "wrong_schema_kind",
      details: "this schema is of kind #{kind}; only document schemas can be issued here"
    })
  end

  defp handle_error(conn, {:error, {:missing_claims, missing}}),
    do: conn |> put_status(422) |> json(%{error: "missing_claims", details: missing})

  defp handle_error(conn, {:error, {:invalid_valid_until, reason}}),
    do:
      conn
      |> put_status(422)
      |> json(%{error: "invalid_valid_until", details: "valid_until #{reason}"})

  defp handle_error(conn, {:error, {:invalid_visibility, _value}}),
    do:
      conn
      |> put_status(422)
      |> json(%{error: "invalid_visibility", details: "must be \"public\" or \"private\""})

  defp handle_error(conn, {:error, %Ecto.Changeset{}}),
    do: conn |> put_status(422) |> json(%{error: "validation_error"})

  defp handle_error(conn, {:error, reason}),
    do: conn |> put_status(422) |> json(%{error: to_string(reason)})
end
