defmodule SovraWeb.Verify.RequestController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Verification

  tags(["Verify"])

  @request_object %OpenApiSpex.Schema{
    type: :string,
    description:
      "Signed OID4VP authorization request (JAR, RFC 9101) as a compact JWS. " <>
        "Header `typ` is `oauth-authz-req+jwt`; the payload carries `client_id`, " <>
        "`response_type`, `response_mode`, `response_uri`, `nonce`, `state`, " <>
        "`dcql_query` and `client_metadata`.",
    example: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJ9.sig"
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:show,
    summary: "Fetch OID4VP authorization request (pass-by-reference)",
    description:
      "Public endpoint that returns the signed OID4VP authorization request " <>
        "object referenced by the short-form QR (`?request_uri=...`). " <>
        "Wallets fetch this when they detect `request_uri` in the URI, and " <>
        "verify the JWS against the key the `client_id` DID resolves to " <>
        "before acting on anything inside it. Returns 404 once the session " <>
        "is past its `expires_at` so wallets don't fall into a stale flow.",
    parameters: [
      session_id: [in: :path, type: :string, required: true]
    ],
    responses: %{
      200 =>
        {"Signed OID4VP authorization request", "application/oauth-authz-req+jwt",
         @request_object},
      404 => {"Session not found or expired", "application/json", @error}
    }
  )

  def show(conn, %{"session_id" => session_id}) do
    with {:ok, session} <- Verification.get_session(session_id),
         false <- expired?(session),
         jwt when is_binary(jwt) <- Verification.build_request_object(session) do
      # OID4VP 1.0 §5.10: the Request URI response carries the signed request
      # object under its own media type, not as JSON.
      conn
      |> put_resp_content_type("application/oauth-authz-req+jwt")
      |> send_resp(200, jwt)
    else
      _ ->
        conn |> put_status(404) |> json(%{error: "session_not_found"})
    end
  end

  defp expired?(session) do
    DateTime.compare(DateTime.utc_now(), session.expires_at) == :gt
  end
end
