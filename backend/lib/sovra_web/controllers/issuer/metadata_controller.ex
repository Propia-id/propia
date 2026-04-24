defmodule SovraWeb.Issuer.MetadataController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer
  alias Sovra.Issuer.OID4VCI
  alias Sovra.Workspaces

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
    case Workspaces.get_first_workspace() do
      {:ok, workspace} ->
        schemas = Issuer.list_schemas(workspace.id)
        metadata = OID4VCI.build_metadata(workspace, schemas)
        json(conn, metadata)

      {:error, :no_workspaces} ->
        conn
        |> put_status(503)
        |> json(%{error: "no_issuers_configured"})
    end
  end

  def show_by_id(conn, %{"issuer_id" => workspace_id}) do
    case Workspaces.get_workspace(workspace_id) do
      {:ok, workspace} ->
        schemas = Issuer.list_schemas(workspace.id)
        metadata = OID4VCI.build_metadata(workspace, schemas)
        json(conn, metadata)

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end
end
