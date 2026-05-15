defmodule SovraWeb.Verify.DirectPostController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Verification

  tags(["Verify"])

  @request_body %OpenApiSpex.Schema{
    type: :object,
    required: [:vp_token, :state],
    properties: %{
      vp_token: %OpenApiSpex.Schema{type: :string, description: "SD-JWT VC + KB-JWT"},
      state: %OpenApiSpex.Schema{type: :string, description: "Session state from the request URI"}
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
        "an OID4VP authorization request. The session is identified by its " <>
        "`state` parameter and cross-checked against the URL `session_id`. " <>
        "Per OID4VP, validation failures still return HTTP 200 \u2014 the verifier " <>
        "learns the outcome via the `presentation.verified` / " <>
        "`presentation.failed` webhook or by polling the session.",
    parameters: [
      session_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"vp_token submission", "application/json", @request_body},
    responses: %{
      200 => {"Submission accepted", "application/json", %OpenApiSpex.Schema{type: :object}},
      400 => {"Malformed request body", "application/json", @error},
      404 => {"Unknown session", "application/json", @error}
    }
  )

  def submit(conn, %{"session_id" => session_id} = params) do
    case fetch_fields(params) do
      {:ok, vp_token, state} ->
        with {:ok, session} <- Verification.get_session_by_state(state),
             true <- session.id == session_id do
          # Always 200 once the session matched: any pipeline failure is
          # reported via webhook, and a resubmission against an already-
          # terminal session is silently ignored — the original outcome
          # already shipped.
          case Verification.submit_presentation(state, vp_token) do
            {:ok, _session} ->
              json(conn, %{})

            {:error, :session_not_pending} ->
              json(conn, %{})

            {:error, :session_not_found} ->
              conn |> put_status(404) |> json(%{error: "session_not_found"})
          end
        else
          {:error, :session_not_found} ->
            conn |> put_status(404) |> json(%{error: "session_not_found"})

          false ->
            conn |> put_status(404) |> json(%{error: "session_not_found"})
        end

      {:error, code} ->
        conn |> put_status(400) |> json(%{error: code})
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
