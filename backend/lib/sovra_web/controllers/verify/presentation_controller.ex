defmodule SovraWeb.Verify.PresentationController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  tags(["Verify"])

  operation(:verify,
    summary: "Verify presentation (not implemented)",
    description: "Verify a verifiable presentation. Not yet implemented.",
    responses: %{
      200 =>
        {"Not implemented", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string, example: "not_implemented"}}
         }}
    }
  )

  operation(:resolve_did,
    summary: "Resolve DID (not implemented)",
    description: "Resolve a DID document. Not yet implemented.",
    parameters: [
      did: [in: :path, type: :string, description: "DID to resolve", required: true]
    ],
    responses: %{
      200 =>
        {"Not implemented", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string, example: "not_implemented"}}
         }}
    }
  )

  def verify(conn, _params) do
    json(conn, %{error: "not_implemented"})
  end

  def resolve_did(conn, %{"did" => _did}) do
    json(conn, %{error: "not_implemented"})
  end
end
