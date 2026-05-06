defmodule SovraWeb.Issuer.AuthServerMetadataController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer.OAuthMetadata
  alias Sovra.Workspaces

  tags(["Authorization Server Metadata"])

  operation(:show_by_id,
    summary: "Get authorization server metadata",
    description:
      "Returns RFC 8414 OAuth 2.0 Authorization Server metadata for the workspace identified by its DID.",
    parameters: [
      workspace_did: [in: :path, type: :string, description: "Workspace DID", required: true]
    ],
    responses: %{
      200 =>
        {"AS metadata", "application/json",
         %OpenApiSpex.Schema{type: :object, description: "OAuth 2.0 AS metadata"}},
      404 =>
        {"Workspace not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def show_by_id(conn, %{"workspace_did" => workspace_did}) do
    case Workspaces.get_workspace_by_did(workspace_did) do
      {:ok, workspace} ->
        json(conn, OAuthMetadata.build_metadata(workspace))

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})
    end
  end
end
