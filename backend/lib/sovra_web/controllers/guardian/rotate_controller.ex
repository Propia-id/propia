defmodule SovraWeb.Guardian.RotateController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  tags(["Recovery"])
  security([%{"BearerAuth" => []}])

  operation(:rotate,
    summary: "Rotate recovery key",
    description:
      "Generate a new recovery key pair. Requires a fresh session (token issued within the last 5 minutes).",
    responses: %{
      200 =>
        {"Key rotated", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             newRecoveryPublicKey: %OpenApiSpex.Schema{
               type: :string,
               description: "Hex-encoded new recovery public key"
             },
             rotationSignature: %OpenApiSpex.Schema{
               type: :string,
               description: "Hex-encoded rotation signature"
             }
           }
         }},
      404 =>
        {"Holder not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      500 =>
        {"Internal error", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def rotate(conn, _params) do
    sovra_address = conn.assigns.current_holder.sovra_address

    case Sovra.Guardian.rotate_recovery_key(sovra_address) do
      {:ok, result} ->
        json(conn, %{
          newRecoveryPublicKey: result.new_recovery_public_key,
          rotationSignature: result.rotation_signature
        })

      {:error, :holder_not_found} ->
        conn |> put_status(404) |> json(%{error: "holder_not_found"})

      {:error, _} ->
        conn |> put_status(500) |> json(%{error: "internal_error"})
    end
  end
end
