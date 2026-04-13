defmodule SovraWeb.Issuer.MetadataController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer
  alias Sovra.Issuer.OID4VCI

  tags(["Issuer Metadata"])

  operation(:show,
    summary: "Get issuer metadata",
    description: "Returns OID4VCI credential issuer metadata for the default issuer.",
    responses: %{
      200 =>
        {"Issuer metadata", "application/json",
         %OpenApiSpex.Schema{type: :object, description: "OID4VCI credential issuer metadata"}},
      503 =>
        {"No issuers configured", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:show_by_id,
    summary: "Get issuer metadata by ID",
    description: "Returns OID4VCI credential issuer metadata for a specific issuer.",
    parameters: [
      issuer_id: [in: :path, type: :string, description: "Issuer UUID", required: true]
    ],
    responses: %{
      200 =>
        {"Issuer metadata", "application/json",
         %OpenApiSpex.Schema{type: :object, description: "OID4VCI credential issuer metadata"}},
      404 =>
        {"Issuer not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def show(conn, _params) do
    case Issuer.get_first_issuer() do
      {:ok, issuer} ->
        schemas = Issuer.list_schemas(issuer.id)
        metadata = OID4VCI.build_metadata(issuer, schemas)
        json(conn, metadata)

      {:error, :no_issuers} ->
        conn
        |> put_status(503)
        |> json(%{error: "no_issuers_configured"})
    end
  end

  def show_by_id(conn, %{"issuer_id" => issuer_id}) do
    case Issuer.get_issuer(issuer_id) do
      {:ok, issuer} ->
        schemas = Issuer.list_schemas(issuer.id)
        metadata = OID4VCI.build_metadata(issuer, schemas)
        json(conn, metadata)

      {:error, :issuer_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end
end
