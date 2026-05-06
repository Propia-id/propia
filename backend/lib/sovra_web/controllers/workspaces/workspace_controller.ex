defmodule SovraWeb.Workspaces.WorkspaceController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Auth.UserSession
  alias Sovra.Workspaces

  tags(["Workspaces"])
  security([%{"UserCookieAuth" => []}])

  @workspace_schema %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      name: %OpenApiSpex.Schema{type: :string},
      did: %OpenApiSpex.Schema{type: :string, nullable: true},
      status: %OpenApiSpex.Schema{type: :string},
      webhook_url: %OpenApiSpex.Schema{type: :string, nullable: true},
      organization_id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      role: %OpenApiSpex.Schema{type: :string, nullable: true}
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

  @create_workspace_response %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      workspace: @workspace_schema,
      webhook_secret: %OpenApiSpex.Schema{
        type: :string,
        description: "Plaintext webhook HMAC secret — returned exactly once"
      }
    }
  }

  operation(:index,
    summary: "List workspaces the caller belongs to",
    responses: %{
      200 =>
        {"Workspaces", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             workspaces: %OpenApiSpex.Schema{type: :array, items: @workspace_schema}
           }
         }},
      401 => {"Missing session", "application/json", @error}
    }
  )

  operation(:list,
    summary: "List all workspaces in an organization",
    description:
      "Org admin/owner view: returns every workspace in the organization, " <>
        "regardless of the caller's per-workspace membership.",
    parameters: [
      org_id: [in: :path, type: :string, required: true, description: "Organization UUID"]
    ],
    responses: %{
      200 =>
        {"Workspaces", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             workspaces: %OpenApiSpex.Schema{type: :array, items: @workspace_schema}
           }
         }},
      401 => {"Missing session", "application/json", @error},
      403 => {"Not an org admin", "application/json", @error},
      404 => {"Organization not found", "application/json", @error}
    }
  )

  operation(:create,
    summary: "Create workspace in an organization",
    description:
      "Creates a workspace under the given organization. Caller becomes the " <>
        "workspace admin. The response carries the plaintext webhook secret " <>
        "exactly once.",
    parameters: [
      org_id: [in: :path, type: :string, required: true, description: "Organization UUID"]
    ],
    request_body:
      {"Workspace params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:name],
         properties: %{
           name: %OpenApiSpex.Schema{type: :string},
           webhook_url: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      201 => {"Workspace created", "application/json", @create_workspace_response},
      401 => {"Missing session", "application/json", @error},
      403 => {"Not an org admin", "application/json", @error},
      404 => {"Organization not found", "application/json", @error},
      422 => {"Validation error", "application/json", @validation_error}
    }
  )

  operation(:show,
    summary: "Show workspace",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true, description: "Workspace UUID"]
    ],
    responses: %{
      200 => {"Workspace", "application/json", @workspace_schema},
      401 => {"Missing session", "application/json", @error},
      403 => {"Not a member", "application/json", @error},
      404 => {"Not found", "application/json", @error}
    }
  )

  operation(:update,
    summary: "Update workspace",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true, description: "Workspace UUID"]
    ],
    request_body:
      {"Workspace fields", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         properties: %{
           name: %OpenApiSpex.Schema{type: :string},
           webhook_url: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      200 => {"Updated", "application/json", @workspace_schema},
      401 => {"Missing session", "application/json", @error},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Not found", "application/json", @error},
      422 => {"Validation error", "application/json", @validation_error}
    }
  )

  operation(:regenerate_webhook_secret,
    summary: "Rotate webhook secret",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true, description: "Workspace UUID"]
    ],
    responses: %{
      200 =>
        {"Rotated", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             webhook_secret: %OpenApiSpex.Schema{type: :string}
           }
         }},
      401 => {"Missing session", "application/json", @error},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Not found", "application/json", @error}
    }
  )

  operation(:switch,
    summary: "Switch current workspace",
    description:
      "Revokes the current session JWT and mints a new one for the selected " <>
        "workspace. The new token is returned as an HTTP-only cookie.",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true, description: "Workspace UUID"]
    ],
    responses: %{
      200 => {"Switched", "application/json", @workspace_schema},
      401 => {"Missing session", "application/json", @error},
      403 => {"Not a member", "application/json", @error}
    }
  )

  @cookie_name "session"
  @cookie_opts [
    http_only: true,
    secure: Application.compile_env(:sovra, :env) == :prod,
    same_site: "Strict",
    path: "/api/v1",
    max_age: 3600
  ]

  def index(conn, _params) do
    user_id = conn.assigns.current_user.user_id
    workspaces = Workspaces.list_workspaces_for_user(user_id)
    json(conn, %{workspaces: workspaces})
  end

  def list(conn, %{"org_id" => org_id}) do
    workspaces =
      org_id
      |> Workspaces.list_workspaces_for_organization()
      |> Enum.map(&workspace_json(&1, nil))

    json(conn, %{workspaces: workspaces})
  end

  def create(conn, %{"org_id" => org_id} = params) do
    user_id = conn.assigns.current_user.user_id

    attrs = %{
      name: params["name"],
      webhook_url: params["webhook_url"]
    }

    case Workspaces.create_workspace(org_id, attrs, user_id) do
      {:ok, %{workspace: workspace, webhook_secret: webhook_secret}} ->
        conn
        |> put_status(201)
        |> json(%{
          workspace: workspace_json(workspace, "admin"),
          webhook_secret: webhook_secret
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        conn |> put_status(422) |> json(%{error: to_string_reason(reason)})
    end
  end

  def show(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user.user_id

    with {:ok, role} <- Workspaces.member_role(workspace_id, user_id),
         {:ok, workspace} <- Workspaces.get_workspace(workspace_id) do
      json(conn, workspace_json(workspace, role))
    else
      {:error, :not_a_member} ->
        conn |> put_status(403) |> json(%{error: "workspace_member_required"})

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})
    end
  end

  def update(conn, %{"workspace_id" => workspace_id} = params) do
    case Workspaces.get_workspace(workspace_id) do
      {:ok, workspace} ->
        attrs = Map.take(params, ["name", "webhook_url"])

        case Workspaces.update_workspace(workspace, atomize(attrs)) do
          {:ok, updated} ->
            json(conn, workspace_json(updated, conn.assigns[:current_workspace_role]))

          {:error, %Ecto.Changeset{} = cs} ->
            conn
            |> put_status(422)
            |> json(%{error: "validation_error", details: changeset_errors(cs)})
        end

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})
    end
  end

  def regenerate_webhook_secret(conn, %{"workspace_id" => workspace_id}) do
    case Workspaces.get_workspace(workspace_id) do
      {:ok, workspace} ->
        case Workspaces.regenerate_webhook_secret(workspace) do
          {:ok, %{webhook_secret: plaintext}} ->
            json(conn, %{webhook_secret: plaintext})

          {:error, reason} ->
            conn |> put_status(500) |> json(%{error: to_string_reason(reason)})
        end

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})
    end
  end

  def switch(conn, %{"workspace_id" => workspace_id}) do
    %{user_id: user_id, is_admin: is_admin} = conn.assigns.current_user

    with {:ok, _role} <- Workspaces.member_role(workspace_id, user_id),
         {:ok, workspace} <- Workspaces.get_workspace(workspace_id),
         {:ok, new_token} <- UserSession.create(user_id, workspace_id, is_admin) do
      _ = UserSession.revoke(conn.assigns[:current_session_token])

      conn
      |> put_resp_cookie(@cookie_name, new_token, @cookie_opts)
      |> json(workspace_json(workspace, nil))
    else
      {:error, :not_a_member} ->
        conn |> put_status(403) |> json(%{error: "workspace_member_required"})

      {:error, :workspace_not_found} ->
        conn |> put_status(404) |> json(%{error: "workspace_not_found"})
    end
  end

  # ── Helpers ────────────────────────────────────────────

  defp workspace_json(workspace, role) do
    %{
      id: workspace.id,
      name: workspace.name,
      did: Map.get(workspace, :did),
      status: Map.get(workspace, :status),
      webhook_url: Map.get(workspace, :webhook_url),
      organization_id: Map.get(workspace, :organization_id),
      role: role
    }
  end

  defp atomize(attrs) do
    for {k, v} <- attrs, into: %{} do
      {String.to_existing_atom(k), v}
    end
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp to_string_reason({atom, detail}) when is_atom(atom), do: "#{atom}: #{inspect(detail)}"
  defp to_string_reason(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp to_string_reason(other), do: inspect(other)
end
