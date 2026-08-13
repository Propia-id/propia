defmodule SovraWeb.Issuer.OfferController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer

  tags(["Issuer OID4VCI"])

  @request_body %OpenApiSpex.Schema{
    type: :object,
    required: [:schema_id],
    properties: %{
      schema_id: %OpenApiSpex.Schema{type: :string},
      claims: %OpenApiSpex.Schema{type: :object}
    }
  }

  @response_body %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      credential_id: %OpenApiSpex.Schema{
        type: :string,
        format: :uuid,
        description:
          "Stable identifier for the credential through its full lifecycle. " <>
            "Echoed in the `credential.issued` webhook and accepted by " <>
            "`GET /credentials/:id` and `PUT /credentials/:id/status/:status`."
      },
      offer_uri: %OpenApiSpex.Schema{type: :string},
      pre_authorized_code: %OpenApiSpex.Schema{type: :string},
      expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
      credential: %OpenApiSpex.Schema{
        type: :object,
        description:
          "Preliminary VC payload (no holder DID, no proof). The signed SD-JWT " <>
            "arrives later in the `credential.issued` webhook."
      }
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:create,
    summary: "Create credential offer",
    description:
      "Create a pre-authorized OID4VCI credential offer. Reachable via dashboard " <>
        "JWT session at `/dashboard/issuer/offers` and via workspace API key " <>
        "(`Authorization: Bearer sovra_sk_...`) at `/api/v1/issuer/credential-offer`.",
    request_body: {"Offer params", "application/json", @request_body},
    responses: %{
      201 => {"Offer created", "application/json", @response_body},
      401 => {"Missing or invalid auth", "application/json", @error},
      404 => {"Schema not found", "application/json", @error},
      422 => {"Validation error", "application/json", @error}
    }
  )

  def create(conn, params) do
    workspace_id = conn.assigns.current_workspace_id

    case Issuer.create_credential_offer(
           workspace_id,
           params["schema_id"],
           params["claims"] || %{}
         ) do
      {:ok,
       %{
         offer: offer,
         offer_uri: offer_uri,
         pre_authorized_code: code,
         credential: credential
       }} ->
        conn
        |> put_status(201)
        |> json(%{
          credential_id: offer.id,
          offer_uri: offer_uri,
          pre_authorized_code: code,
          expires_at: DateTime.to_iso8601(offer.expires_at),
          credential: credential
        })

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})

      {:error, :workspace_not_provisioned} ->
        conn |> put_status(409) |> json(%{error: "workspace_not_provisioned"})

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})

      {:error, {:missing_claims, missing}} ->
        conn |> put_status(422) |> json(%{error: "missing_claims", details: missing})

      {:error, {:wrong_schema_kind, kind}} ->
        conn
        |> put_status(422)
        |> json(%{
          error: "wrong_schema_kind",
          details:
            "this schema is of kind #{kind}; only credential schemas can be offered to a wallet"
        })

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: to_string(reason)})
    end
  end
end
