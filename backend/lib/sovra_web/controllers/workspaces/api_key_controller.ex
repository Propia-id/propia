defmodule SovraWeb.Workspaces.ApiKeyController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Workspaces.ApiKeys

  tags(["Workspace API Keys"])
  security([%{"IssuerCookieAuth" => []}])

  @api_key_record %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      name: %OpenApiSpex.Schema{type: :string},
      last_used_at: %OpenApiSpex.Schema{type: :string, format: :"date-time", nullable: true},
      revoked_at: %OpenApiSpex.Schema{type: :string, format: :"date-time", nullable: true},
      inserted_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"}
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:index,
    summary: "List API keys",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: %{
      200 =>
        {"API keys", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             api_keys: %OpenApiSpex.Schema{type: :array, items: @api_key_record}
           }
         }},
      403 => {"Not an admin", "application/json", @error}
    }
  )

  operation(:create,
    summary: "Create API key",
    description: "Returns the plaintext key exactly once alongside the record.",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"API key params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:name],
         properties: %{name: %OpenApiSpex.Schema{type: :string}}
       }},
    responses: %{
      201 =>
        {"Created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             api_key: %OpenApiSpex.Schema{type: :string},
             record: @api_key_record
           }
         }},
      403 => {"Not an admin", "application/json", @error},
      422 => {"Validation error", "application/json", @error}
    }
  )

  operation(:revoke,
    summary: "Revoke API key",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      id: [in: :path, type: :string, required: true]
    ],
    responses: %{
      200 => {"Revoked", "application/json", @api_key_record},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Not found", "application/json", @error}
    }
  )

  def index(conn, %{"workspace_id" => workspace_id}) do
    api_keys = ApiKeys.list_api_keys(workspace_id)
    json(conn, %{api_keys: Enum.map(api_keys, &record_json/1)})
  end

  def create(conn, %{"workspace_id" => workspace_id, "name" => name}) do
    case ApiKeys.create_api_key(workspace_id, name) do
      {:ok, %{api_key: plaintext, record: record}} ->
        conn
        |> put_status(201)
        |> json(%{api_key: plaintext, record: record_json(record)})

      {:error, %Ecto.Changeset{} = cs} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(cs)})
    end
  end

  def create(conn, _params) do
    conn |> put_status(422) |> json(%{error: "name_required"})
  end

  def revoke(conn, %{"workspace_id" => workspace_id, "id" => id}) do
    with {:ok, record} <- ApiKeys.get_api_key(workspace_id, id),
         {:ok, updated} <- ApiKeys.revoke_api_key(record) do
      json(conn, record_json(updated))
    else
      {:error, :not_found} ->
        conn |> put_status(404) |> json(%{error: "api_key_not_found"})
    end
  end

  defp record_json(%Sovra.Workspaces.ApiKey{} = r) do
    %{
      id: r.id,
      name: r.name,
      last_used_at: r.last_used_at && DateTime.to_iso8601(r.last_used_at),
      revoked_at: r.revoked_at && DateTime.to_iso8601(r.revoked_at),
      inserted_at: DateTime.to_iso8601(r.inserted_at)
    }
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
