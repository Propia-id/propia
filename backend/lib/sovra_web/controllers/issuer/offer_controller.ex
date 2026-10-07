defmodule SovraWeb.Issuer.OfferController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer
  alias Sovra.Issuer.ClaimUtils
  alias Sovra.Issuer.ClaimValue

  tags(["Issuer OID4VCI"])

  @request_body %OpenApiSpex.Schema{
    type: :object,
    required: [:schema_id],
    properties: %{
      schema_id: %OpenApiSpex.Schema{type: :string},
      claims: %OpenApiSpex.Schema{type: :object},
      valid_until: %OpenApiSpex.Schema{
        type: :string,
        format: :"date-time",
        description:
          "Optional absolute expiry for this credential, overriding the schema's " <>
            "`validity_period`. Use it to re-issue a credential keeping the original " <>
            "expiration, which a relative period cannot express — the offer is " <>
            "redeemed at an unknown later time. Must be in the future. Omit the " <>
            "field to derive expiry from the schema as before; `null` is rejected."
      }
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
      409 =>
        {"Workspace not provisioned, or the schema's credential type is not registered " <>
           "on-chain yet (`schema_registration_pending`) or could not be " <>
           "(`schema_registration_failed`)", "application/json", @error},
      422 => {"Validation error", "application/json", @error}
    }
  )

  @regenerated_body %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      credential_id: %OpenApiSpex.Schema{
        type: :string,
        format: :uuid,
        description: "Unchanged — the same credential id the offer was created with."
      },
      offer_uri: %OpenApiSpex.Schema{type: :string},
      pre_authorized_code: %OpenApiSpex.Schema{type: :string},
      expires_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"}
    }
  }

  operation(:regenerate,
    summary: "Regenerate a credential offer's QR",
    description:
      "Re-mint the pre-authorized code of an unclaimed offer and return a fresh " <>
        "`offer_uri`. The offer URI carries the plaintext code and only its hash is " <>
        "stored, so a QR that has been closed cannot otherwise be shown again. The " <>
        "offer keeps its credential id and status list index; **any code already " <>
        "shared for it stops working**. Only a `pending`, unexpired offer can be " <>
        "regenerated.",
    parameters: [
      id: [in: :path, type: %OpenApiSpex.Schema{type: :string, format: :uuid}, required: true]
    ],
    responses: %{
      200 => {"Offer regenerated", "application/json", @regenerated_body},
      401 => {"Missing or invalid auth", "application/json", @error},
      404 => {"Offer not found", "application/json", @error},
      409 => {"Offer already claimed or expired", "application/json", @error}
    }
  )

  def regenerate(conn, %{"id" => id}) do
    # A malformed UUID would raise Ecto.Query.CastError on the lookup; it is a
    # 404 for the same reason an unknown id is.
    case Ecto.UUID.cast(id) do
      :error ->
        conn |> put_status(404) |> json(%{error: "offer_not_found"})

      {:ok, offer_id} ->
        regenerate_offer(conn, conn.assigns.current_workspace_id, offer_id)
    end
  end

  defp regenerate_offer(conn, workspace_id, offer_id) do
    case Issuer.regenerate_offer_code(workspace_id, offer_id) do
      {:ok, %{offer: offer, offer_uri: offer_uri, pre_authorized_code: code}} ->
        json(conn, %{
          credential_id: offer.id,
          offer_uri: offer_uri,
          pre_authorized_code: code,
          expires_at: DateTime.to_iso8601(offer.expires_at)
        })

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})

      {:error, :workspace_not_provisioned} ->
        conn |> put_status(409) |> json(%{error: "workspace_not_provisioned"})

      {:error, :offer_not_found} ->
        conn |> put_status(404) |> json(%{error: "offer_not_found"})

      {:error, :offer_expired} ->
        conn
        |> put_status(409)
        |> json(%{
          error: "offer_expired",
          details: "this offer's pickup window has closed; issue a new credential instead"
        })

      {:error, {:offer_not_pending, status}} ->
        conn
        |> put_status(409)
        |> json(%{
          error: "offer_not_pending",
          details:
            "this offer is #{status}; a holder has already started claiming it, " <>
              "so its QR can no longer be reissued"
        })

      {:error, %Ecto.Changeset{}} ->
        conn |> put_status(422) |> json(%{error: "offer_regeneration_failed"})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: to_string(reason)})
    end
  end

  def create(conn, params) do
    workspace_id = conn.assigns.current_workspace_id

    with {:ok, valid_until} <- fetch_valid_until(params) do
      create_offer(conn, workspace_id, params, valid_until)
    else
      {:error, {:invalid_valid_until, reason}} ->
        conn
        |> put_status(422)
        |> json(%{error: "invalid_valid_until", details: "valid_until #{reason}"})
    end
  end

  # Absent and null are kept distinct, as they are for a schema's
  # `validity_period`: omitting the field asks for the schema default, while an
  # explicit null is a caller describing an expiry it could not compute. Issuing
  # the default for it would hand back a date nobody chose.
  defp fetch_valid_until(params) do
    case Map.fetch(params, "valid_until") do
      :error -> {:ok, nil}
      {:ok, value} -> ClaimUtils.parse_valid_until(value) |> tag_error()
    end
  end

  defp tag_error({:ok, valid_until}), do: {:ok, valid_until}
  defp tag_error({:error, reason}), do: {:error, {:invalid_valid_until, reason}}

  defp create_offer(conn, workspace_id, params, valid_until) do
    case Issuer.create_credential_offer(
           workspace_id,
           params["schema_id"],
           params["claims"] || %{},
           valid_until: valid_until
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

      {:error, reason}
      when reason in [:schema_registration_pending, :schema_registration_failed] ->
        conn |> put_status(409) |> json(schema_registration_error(reason))

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

      {:error, {:unencodable_claims, keys}} ->
        conn
        |> put_status(422)
        |> json(%{
          error: "unencodable_claims",
          details:
            "these values cannot be encoded as ISO 18013-5 CBOR: #{Enum.join(keys, ", ")}. " <>
              "Numbers must be whole, dates must be ISO 8601."
        })

      {:error, {:invalid_claim_values, reasons}} ->
        conn
        |> put_status(422)
        |> json(%{
          error: "invalid_claim_values",
          details: Enum.map(reasons, fn {key, reason} -> "#{key}: #{claim_reason(reason)}" end)
        })

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: to_string(reason)})
    end
  end

  defp schema_registration_error(:schema_registration_pending),
    do: %{
      error: "schema_registration_pending",
      details:
        "the schema's credential type is still being registered on-chain; retry in a few seconds"
    }

  defp schema_registration_error(:schema_registration_failed),
    do: %{
      error: "schema_registration_failed",
      details:
        "the schema's credential type could not be registered on-chain, so nothing can be issued from it"
    }

  # An operator reads these, so they say what to do rather than naming the check
  # that failed.
  defp claim_reason(:not_a_string), do: "an attachment must be sent as a data: URI string"

  defp claim_reason(:not_a_data_uri),
    do: "an attachment must be a data: URI, base64-encoded, with no whitespace"

  defp claim_reason(:unsupported_media_type),
    do: "only #{Enum.join(ClaimValue.attachment_media_types(), ", ")} attachments are accepted"

  defp claim_reason(:too_large) do
    kb = div(ClaimValue.max_attachment_uri_bytes(), 1024)
    "the attachment is too large; the encoded value must be #{kb} KB or less"
  end

  defp claim_reason(other), do: to_string(other)
end
