defmodule SovraWeb.Verify.RequestController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Verification

  tags(["Verify"])

  @request_object %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      client_id: %OpenApiSpex.Schema{type: :string},
      response_type: %OpenApiSpex.Schema{type: :string},
      response_mode: %OpenApiSpex.Schema{type: :string},
      response_uri: %OpenApiSpex.Schema{type: :string},
      nonce: %OpenApiSpex.Schema{type: :string},
      state: %OpenApiSpex.Schema{type: :string},
      dcql_query: %OpenApiSpex.Schema{type: :object}
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:show,
    summary: "Fetch OID4VP authorization request (pass-by-reference)",
    description:
      "Public endpoint that returns the OID4VP authorization request " <>
        "object referenced by the short-form QR (`?request_uri=...`). " <>
        "Wallets fetch this when they detect `request_uri` in the URI. " <>
        "Returns 404 once the session is past its `expires_at` so wallets " <>
        "don't fall into a stale flow.",
    parameters: [
      session_id: [in: :path, type: :string, required: true]
    ],
    responses: %{
      200 => {"OID4VP authorization request", "application/json", @request_object},
      404 => {"Session not found or expired", "application/json", @error}
    }
  )

  def show(conn, %{"session_id" => session_id}) do
    with {:ok, session} <- Verification.get_session(session_id),
         false <- expired?(session) do
      json(conn, Verification.build_request_object(session))
    else
      _ ->
        conn |> put_status(404) |> json(%{error: "session_not_found"})
    end
  end

  defp expired?(session) do
    DateTime.compare(DateTime.utc_now(), session.expires_at) == :gt
  end
end
