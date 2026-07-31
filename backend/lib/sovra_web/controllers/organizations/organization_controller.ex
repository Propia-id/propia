defmodule SovraWeb.Organizations.OrganizationController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Organizations

  tags(["Organizations"])
  security([%{"UserCookieAuth" => []}])

  @org_schema %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      name: %OpenApiSpex.Schema{type: :string},
      logo_url: %OpenApiSpex.Schema{type: :string, nullable: true},
      website: %OpenApiSpex.Schema{type: :string, nullable: true},
      status: %OpenApiSpex.Schema{type: :string},
      role: %OpenApiSpex.Schema{
        type: :string,
        nullable: true,
        description: "Caller's role in this organization, when applicable"
      }
    }
  }

  @validation_error %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      error: %OpenApiSpex.Schema{type: :string},
      details: %OpenApiSpex.Schema{type: :object}
    }
  }

  @error_schema %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:create,
    summary: "Create organization",
    description: """
    Creates an organization. The authenticated user becomes its owner.

    Disabled by default: answers 403 `organization_creation_disabled` unless the
    deployment sets ORGANIZATION_CREATION_ENABLED=true.
    """,
    request_body:
      {"Organization params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:name],
         properties: %{
           name: %OpenApiSpex.Schema{type: :string},
           logo_url: %OpenApiSpex.Schema{type: :string},
           website: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      201 => {"Organization created", "application/json", @org_schema},
      401 => {"Missing session", "application/json", @error_schema},
      403 => {"Organization creation disabled", "application/json", @error_schema},
      422 => {"Validation error", "application/json", @validation_error}
    }
  )

  operation(:index,
    summary: "List organizations the caller belongs to",
    responses: %{
      200 =>
        {"Organization list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             organizations: %OpenApiSpex.Schema{type: :array, items: @org_schema}
           }
         }},
      401 => {"Missing session", "application/json", @error_schema}
    }
  )

  operation(:show,
    summary: "Get organization",
    parameters: [
      org_id: [in: :path, type: :string, description: "Organization UUID", required: true]
    ],
    responses: %{
      200 => {"Organization", "application/json", @org_schema},
      401 => {"Missing session", "application/json", @error_schema},
      403 => {"Not a member", "application/json", @error_schema},
      404 => {"Not found", "application/json", @error_schema}
    }
  )

  operation(:update,
    summary: "Update organization branding",
    description: "Update the organization's name, logo URL, or website. Org admin required.",
    parameters: [
      org_id: [in: :path, type: :string, description: "Organization UUID", required: true]
    ],
    request_body:
      {"Organization params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         properties: %{
           name: %OpenApiSpex.Schema{type: :string},
           logo_url: %OpenApiSpex.Schema{type: :string},
           website: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      200 => {"Updated", "application/json", @org_schema},
      401 => {"Missing session", "application/json", @error_schema},
      403 => {"Org admin required", "application/json", @error_schema},
      404 => {"Not found", "application/json", @error_schema},
      422 => {"Validation error", "application/json", @validation_error}
    }
  )

  operation(:deactivate,
    summary: "Deactivate organization",
    description: "Deactivates the organization. Org owner required.",
    parameters: [
      org_id: [in: :path, type: :string, description: "Organization UUID", required: true]
    ],
    responses: %{
      200 => {"Deactivated", "application/json", @org_schema},
      401 => {"Missing session", "application/json", @error_schema},
      403 => {"Org owner required", "application/json", @error_schema},
      404 => {"Not found", "application/json", @error_schema}
    }
  )

  operation(:list_members,
    summary: "List organization members",
    parameters: [
      org_id: [in: :path, type: :string, description: "Organization UUID", required: true]
    ],
    responses: %{
      200 =>
        {"Member list", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             members: %OpenApiSpex.Schema{
               type: :array,
               items: %OpenApiSpex.Schema{
                 type: :object,
                 properties: %{
                   id: %OpenApiSpex.Schema{type: :string, format: :uuid},
                   email: %OpenApiSpex.Schema{type: :string},
                   role: %OpenApiSpex.Schema{type: :string},
                   status: %OpenApiSpex.Schema{type: :string}
                 }
               }
             }
           }
         }},
      401 => {"Missing session", "application/json", @error_schema},
      403 => {"Org admin required", "application/json", @error_schema}
    }
  )

  def create(conn, params) do
    if Organizations.creation_enabled?() do
      do_create(conn, params)
    else
      conn |> put_status(403) |> json(%{error: "organization_creation_disabled"})
    end
  end

  defp do_create(conn, params) do
    user_id = conn.assigns.current_user.user_id

    attrs = %{
      name: params["name"],
      logo_url: params["logo_url"],
      website: params["website"]
    }

    case Organizations.create_organization(user_id, attrs) do
      {:ok, %{organization: org, membership: mem}} ->
        conn |> put_status(201) |> json(org_json(org, mem.role))

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def index(conn, _params) do
    user_id = conn.assigns.current_user.user_id
    organizations = Organizations.list_organizations_for_user(user_id)
    json(conn, %{organizations: organizations})
  end

  def show(conn, %{"org_id" => org_id}) do
    user_id = conn.assigns.current_user.user_id

    with {:ok, role} <- Organizations.member_role(org_id, user_id),
         {:ok, org} <- Organizations.get_organization(org_id) do
      json(conn, org_json(org, role))
    else
      {:error, :not_a_member} ->
        conn |> put_status(403) |> json(%{error: "org_admin_required"})

      {:error, :not_found} ->
        conn |> put_status(404) |> json(%{error: "organization_not_found"})
    end
  end

  def update(conn, %{"org_id" => org_id} = params) do
    case Organizations.get_organization(org_id) do
      {:ok, org} ->
        attrs =
          %{}
          |> maybe_put(:name, params["name"])
          |> maybe_put(:logo_url, params["logo_url"])
          |> maybe_put(:website, params["website"])

        case Organizations.update_organization(org, attrs) do
          {:ok, updated} ->
            json(conn, org_json(updated, conn.assigns[:current_org_role]))

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(422)
            |> json(%{error: "validation_error", details: changeset_errors(changeset)})
        end

      {:error, :not_found} ->
        conn |> put_status(404) |> json(%{error: "organization_not_found"})
    end
  end

  def deactivate(conn, %{"org_id" => org_id}) do
    case Organizations.get_organization(org_id) do
      {:ok, org} ->
        {:ok, updated} = Organizations.deactivate_organization(org)
        json(conn, org_json(updated, conn.assigns[:current_org_role]))

      {:error, :not_found} ->
        conn |> put_status(404) |> json(%{error: "organization_not_found"})
    end
  end

  def list_members(conn, %{"org_id" => org_id}) do
    members = Organizations.list_members(org_id)
    json(conn, %{members: members})
  end

  defp org_json(org, role) do
    %{
      id: org.id,
      name: org.name,
      logo_url: org.logo_url,
      website: org.website,
      status: org.status,
      role: role
    }
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
