defmodule SovraWeb.Verify.DirectPostController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Verification
  alias Sovra.Verification.Session

  tags(["Verify"])

  @request_body %OpenApiSpex.Schema{
    type: :object,
    required: [:vp_token, :state],
    properties: %{
      vp_token: %OpenApiSpex.Schema{
        type: :string,
        description:
          "JSON object keyed by the DCQL credential id, whose value is the presentation " <>
            "(SD-JWT VC + KB-JWT, or a base64url mdoc DeviceResponse)"
      },
      state: %OpenApiSpex.Schema{type: :string, description: "Session state from the request URI"}
    }
  }

  # The holder is told why a presentation was rejected in enough detail to act
  # on — renew the credential, scan again, try later, pick another credential —
  # and no more. Every tag naming a failed cryptographic or binding check
  # collapses into `invalid_presentation`, so the endpoint cannot be used to
  # learn which check a crafted presentation tripped; an honest wallet cannot
  # act on those anyway. A tag added to the pipeline later lands there too until
  # it is placed deliberately. The verifier keeps the full tag through the
  # webhook and the session.
  @passed_through ~w(credential_expired credential_revoked credential_suspended
                     session_expired unknown_issuer)
  @request_not_satisfied ~w(missing_required_claim format_mismatch doctype_mismatch)
  # Our dependencies failed, or the verifier's own query is malformed.
  @verifier_error ~w(holder_did_unresolvable status_check_failed invalid_dcql_query)

  @reasons @passed_through ++ ~w(request_not_satisfied verifier_error invalid_presentation)

  @submission_result %OpenApiSpex.Schema{
    type: :object,
    required: [:verification_result],
    properties: %{
      verification_result: %OpenApiSpex.Schema{
        type: :string,
        enum: ["verified", "rejected", "already_answered"],
        description:
          "The verifier's verdict on this submission. `already_answered` means the " <>
            "session had already reached a verdict, which this submission did not change."
      },
      reason: %OpenApiSpex.Schema{
        type: :string,
        enum: @reasons,
        description: "Present when `verification_result` is `rejected`."
      }
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:submit,
    summary: "Wallet direct_post submission",
    description:
      "Public endpoint where a holder wallet posts a vp_token in response to " <>
        "an OID4VP authorization request (OID4VP 1.0 §8.2). The session is " <>
        "identified by its `state` parameter and cross-checked against the URL " <>
        "`session_id`. A presentation that fails validation is still a processed " <>
        "response, so it returns HTTP 200 with `verification_result: rejected`. " <>
        "The verdict fields are a Sovra extension the spec permits; other wallets " <>
        "ignore them. The verifier learns the full outcome via the " <>
        "`presentation.verified` / `presentation.failed` webhook or by polling the session.",
    parameters: [
      session_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"vp_token submission", "application/x-www-form-urlencoded", @request_body},
    responses: %{
      200 => {"Submission processed", "application/json", @submission_result},
      400 => {"Malformed request body", "application/json", @error},
      404 => {"Unknown session", "application/json", @error},
      415 => {"Body is not form-encoded", "application/json", @error}
    }
  )

  def submit(conn, %{"session_id" => session_id} = params) do
    with :ok <- check_content_type(conn),
         {:ok, vp_token, state} <- fetch_fields(params),
         {:ok, session} <- Verification.get_session_by_state(state),
         true <- session.id == session_id do
      case Verification.submit_presentation(state, vp_token) do
        {:ok, session} ->
          respond(conn, verdict(session))

        {:error, :session_not_pending} ->
          respond(conn, unchanged_verdict(session))

        {:error, :session_not_found} ->
          session_not_found(conn)
      end
    else
      {:error, :unsupported_media_type} ->
        conn |> put_status(415) |> json(%{error: "unsupported_media_type"})

      {:error, :session_not_found} ->
        session_not_found(conn)

      false ->
        session_not_found(conn)

      {:error, code} ->
        conn |> put_status(400) |> json(%{error: code})
    end
  end

  # OID4VP 1.0 §8.2 has the wallet form-encode the Authorization Response.
  #
  # The JSON clause is transitional, not a second accepted form: wallets
  # released before the wallet switched to form encoding still post JSON, and
  # an installed app keeps running its old bundle until it takes an update.
  # Delete the clause once those releases are out of support.
  defp check_content_type(conn) do
    with [header | _] <- get_req_header(conn, "content-type"),
         {:ok, "application", subtype, _params} when subtype in ["x-www-form-urlencoded", "json"] <-
           Plug.Conn.Utils.content_type(header) do
      :ok
    else
      _ -> {:error, :unsupported_media_type}
    end
  end

  # The example response in §8.2 carries it, and the body is now a verdict
  # about one holder's presentation.
  defp respond(conn, body) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> json(body)
  end

  defp session_not_found(conn) do
    conn |> put_status(404) |> json(%{error: "session_not_found"})
  end

  defp verdict(%Session{status: "completed"}), do: %{verification_result: "verified"}

  defp verdict(%Session{status: "failed", error: tag}),
    do: %{verification_result: "rejected", reason: holder_reason(tag)}

  # The sweeper marks a lapsed session `expired` without a verdict, so to the
  # holder this is a scan that came too late, not a request already answered.
  defp unchanged_verdict(%Session{status: "expired"}),
    do: %{verification_result: "rejected", reason: "session_expired"}

  # A resubmission against a session that already reached a verdict is ignored
  # — the original outcome already shipped. Repeating it here would hand anyone
  # holding the QR's `state` the verdict on someone else's presentation.
  defp unchanged_verdict(_session), do: %{verification_result: "already_answered"}

  defp holder_reason(tag) do
    # Some tags carry a detail after the colon, such as the missing claim path.
    case tag |> String.split(":", parts: 2) |> hd() do
      reason when reason in @passed_through -> reason
      reason when reason in @request_not_satisfied -> "request_not_satisfied"
      reason when reason in @verifier_error -> "verifier_error"
      _ -> "invalid_presentation"
    end
  end

  defp fetch_fields(params) do
    case {Map.get(params, "vp_token"), Map.get(params, "state")} do
      {vp, state} when is_binary(vp) and is_binary(state) and vp != "" and state != "" ->
        {:ok, vp, state}

      {nil, _} ->
        {:error, "missing_vp_token"}

      {_, nil} ->
        {:error, "missing_state"}

      _ ->
        {:error, "invalid_request"}
    end
  end
end
