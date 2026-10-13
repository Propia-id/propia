defmodule SovraWeb.Workspaces.WebhookController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Webhooks
  alias Sovra.Webhooks.Webhook

  tags(["Workspace Webhooks"])
  security([%{"UserCookieAuth" => []}])

  @webhook_record %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      url: %OpenApiSpex.Schema{type: :string},
      events: %OpenApiSpex.Schema{
        type: :array,
        items: %OpenApiSpex.Schema{type: :string, enum: Webhooks.event_types()}
      },
      enabled: %OpenApiSpex.Schema{type: :boolean},
      inserted_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
      updated_at: %OpenApiSpex.Schema{type: :string, format: :"date-time"}
    }
  }

  @webhook_params %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      url: %OpenApiSpex.Schema{type: :string},
      events: %OpenApiSpex.Schema{
        type: :array,
        items: %OpenApiSpex.Schema{type: :string, enum: Webhooks.event_types()},
        description: "Event types delivered to this endpoint. At least one."
      },
      enabled: %OpenApiSpex.Schema{type: :boolean}
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  @validation_error %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      error: %OpenApiSpex.Schema{type: :string},
      details: %OpenApiSpex.Schema{type: :object}
    }
  }

  @workspace_id [in: :path, type: :string, required: true, description: "Workspace UUID"]
  @id [in: :path, type: :string, required: true, description: "Webhook UUID"]

  operation(:index,
    summary: "List webhook endpoints",
    parameters: [workspace_id: @workspace_id],
    responses: %{
      200 =>
        {"Webhooks", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             webhooks: %OpenApiSpex.Schema{type: :array, items: @webhook_record}
           }
         }},
      403 => {"Not an admin", "application/json", @error},
      409 => {"Workspace or organization inactive", "application/json", @error}
    }
  )

  operation(:create,
    summary: "Create webhook endpoint",
    description: "Returns the plaintext signing secret exactly once alongside the record.",
    parameters: [workspace_id: @workspace_id],
    request_body: {"Webhook params", "application/json", @webhook_params},
    responses: %{
      201 =>
        {"Created", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             webhook: @webhook_record,
             secret: %OpenApiSpex.Schema{type: :string}
           }
         }},
      403 => {"Not an admin", "application/json", @error},
      409 => {"Workspace or organization inactive", "application/json", @error},
      422 => {"Validation error or endpoint limit reached", "application/json", @validation_error}
    }
  )

  operation(:update,
    summary: "Update webhook endpoint",
    parameters: [workspace_id: @workspace_id, id: @id],
    request_body: {"Webhook fields", "application/json", @webhook_params},
    responses: %{
      200 => {"Updated", "application/json", @webhook_record},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Not found", "application/json", @error},
      409 => {"Workspace or organization inactive", "application/json", @error},
      422 => {"Validation error", "application/json", @validation_error}
    }
  )

  operation(:delete,
    summary: "Delete webhook endpoint",
    parameters: [workspace_id: @workspace_id, id: @id],
    responses: %{
      204 => "Deleted",
      403 => {"Not an admin", "application/json", @error},
      404 => {"Not found", "application/json", @error},
      409 => {"Workspace or organization inactive", "application/json", @error}
    }
  )

  operation(:rotate_secret,
    summary: "Rotate webhook endpoint secret",
    description:
      "Returns the new plaintext signing secret exactly once. The previous " <>
        "secret stops verifying immediately.",
    parameters: [workspace_id: @workspace_id, id: @id],
    responses: %{
      200 =>
        {"Rotated", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{secret: %OpenApiSpex.Schema{type: :string}}
         }},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Not found", "application/json", @error},
      409 => {"Workspace or organization inactive", "application/json", @error}
    }
  )

  @fields ["url", "events", "enabled"]

  def index(conn, %{"workspace_id" => workspace_id}) do
    case Webhooks.list_webhooks(workspace_id) do
      {:ok, webhooks} -> json(conn, %{webhooks: Enum.map(webhooks, &webhook_json/1)})
      error -> respond_error(conn, error)
    end
  end

  def create(conn, %{"workspace_id" => workspace_id} = params) do
    case Webhooks.create_webhook(workspace_id, Map.take(params, @fields)) do
      {:ok, %{webhook: webhook, secret: secret}} ->
        conn
        |> put_status(201)
        |> json(%{webhook: webhook_json(webhook), secret: secret})

      error ->
        respond_error(conn, error)
    end
  end

  def update(conn, %{"workspace_id" => workspace_id, "id" => id} = params) do
    case Webhooks.update_webhook(workspace_id, id, Map.take(params, @fields)) do
      {:ok, webhook} -> json(conn, webhook_json(webhook))
      error -> respond_error(conn, error)
    end
  end

  def delete(conn, %{"workspace_id" => workspace_id, "id" => id}) do
    case Webhooks.delete_webhook(workspace_id, id) do
      {:ok, _} -> send_resp(conn, 204, "")
      error -> respond_error(conn, error)
    end
  end

  def rotate_secret(conn, %{"workspace_id" => workspace_id, "id" => id}) do
    case Webhooks.rotate_webhook_secret(workspace_id, id) do
      {:ok, %{secret: secret}} -> json(conn, %{secret: secret})
      error -> respond_error(conn, error)
    end
  end

  defp respond_error(conn, {:error, %Ecto.Changeset{} = cs}) do
    conn
    |> put_status(422)
    |> json(%{error: "validation_error", details: changeset_errors(cs)})
  end

  defp respond_error(conn, {:error, :webhook_limit_reached}),
    do: conn |> put_status(422) |> json(%{error: "webhook_limit_reached"})

  defp respond_error(conn, {:error, :webhook_not_found}),
    do: conn |> put_status(404) |> json(%{error: "webhook_not_found"})

  defp respond_error(conn, {:error, reason})
       when reason in [:workspace_inactive, :organization_inactive, :workspace_not_found],
       do: conn |> put_status(409) |> json(%{error: to_string(reason)})

  defp webhook_json(%Webhook{} = w) do
    %{
      id: w.id,
      url: w.url,
      events: w.events,
      enabled: w.enabled,
      inserted_at: DateTime.to_iso8601(w.inserted_at),
      updated_at: DateTime.to_iso8601(w.updated_at)
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
