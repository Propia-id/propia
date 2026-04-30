defmodule SovraWeb.Issuer.ManifestController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer
  alias Sovra.Workspaces

  tags(["Issuer Manifest"])

  operation(:index,
    summary: "List DIF credential manifests",
    description:
      "Returns DIF Credential Manifest output_descriptors for all schemas with a design " <>
        "configured (for the default issuer). Consumed by wallets to render credentials.",
    responses: %{
      200 =>
        {"Output descriptors", "application/json",
         %OpenApiSpex.Schema{type: :object, description: "DIF credential manifest"}},
      503 =>
        {"No issuers configured", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  operation(:show,
    summary: "Get DIF output_descriptor by schema",
    description:
      "Returns a DIF Credential Manifest output_descriptor for a single schema (default issuer).",
    parameters: [
      schema_id: [in: :path, type: :string, description: "Schema identifier", required: true]
    ],
    responses: %{
      200 =>
        {"Output descriptor", "application/json",
         %OpenApiSpex.Schema{type: :object, description: "DIF output_descriptor"}},
      404 =>
        {"Not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  def index(conn, _params) do
    case Workspaces.get_first_workspace() do
      {:ok, workspace} ->
        descriptors =
          workspace.id
          |> Issuer.list_designs()
          |> Enum.map(&to_output_descriptor/1)

        json(conn, %{
          issuer: %{id: workspace.id, name: workspace.name, did: workspace.did},
          output_descriptors: descriptors
        })

      {:error, :no_workspaces} ->
        conn |> put_status(503) |> json(%{error: "no_issuers_configured"})
    end
  end

  def show(conn, %{"schema_id" => schema_id}) do
    with {:ok, workspace} <- Workspaces.get_first_workspace(),
         {:ok, design} <- Issuer.get_design(workspace.id, schema_id) do
      json(conn, to_output_descriptor(design))
    else
      {:error, :no_workspaces} ->
        conn |> put_status(503) |> json(%{error: "no_issuers_configured"})

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})

      {:error, :design_not_found} ->
        conn |> put_status(404) |> json(%{error: "design_not_found"})
    end
  end

  defp to_output_descriptor(design) do
    %{
      "id" => design.id,
      "schema" => design.credential_schema.schema_id,
      "name" => design.name,
      "description" => design.description,
      "display" => embed_to_map(design.display),
      "styles" => embed_to_map(design.styles),
      "sovra:back" => embed_to_map(design.back)
    }
    |> drop_nil_values()
  end

  defp drop_nil_values(map) do
    Enum.reject(map, fn {_k, v} -> is_nil(v) end) |> Map.new()
  end

  defp embed_to_map(nil), do: nil

  defp embed_to_map(struct) when is_struct(struct) do
    struct
    |> Map.from_struct()
    |> Map.drop([:__meta__])
    |> Map.new(fn {k, v} -> {k, embed_value(v)} end)
    |> drop_nil_values()
  end

  defp embed_value(nil), do: nil
  defp embed_value(list) when is_list(list), do: Enum.map(list, &embed_value/1)
  defp embed_value(%DateTime{} = dt), do: dt
  defp embed_value(%Date{} = d), do: d
  defp embed_value(%NaiveDateTime{} = dt), do: dt
  defp embed_value(struct) when is_struct(struct), do: embed_to_map(struct)
  defp embed_value(other), do: other
end
