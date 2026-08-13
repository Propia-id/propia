defmodule SovraWeb.Issuer.MetadataController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer
  alias Sovra.Issuer.OID4VCI
  alias Sovra.Workspaces

  tags(["Issuer Metadata"])

  operation(:show_by_id,
    summary: "Get issuer metadata by workspace DID",
    description:
      "Returns OID4VCI credential issuer metadata for the workspace identified by its DID.",
    parameters: [
      workspace_did: [in: :path, type: :string, description: "Workspace DID", required: true]
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

  def show_by_id(conn, %{"workspace_did" => workspace_did}) do
    case Workspaces.get_workspace_by_did(workspace_did) do
      {:ok, workspace} ->
        # Credentials only: a document has no wallet flow, so advertising one
        # here would offer a wallet something it can never collect.
        schemas = Issuer.list_schemas(workspace.id, "credential")
        designs = Issuer.list_designs(workspace.id)
        metadata = OID4VCI.build_metadata(workspace, schemas, designs)
        json(conn, metadata)

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end
end
