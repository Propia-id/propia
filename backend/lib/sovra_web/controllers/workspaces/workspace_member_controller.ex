defmodule SovraWeb.Workspaces.WorkspaceMemberController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer.IssuerAccount
  alias Sovra.Repo
  alias Sovra.Workspaces

  tags(["Workspace Members"])
  security([%{"IssuerCookieAuth" => []}])

  @member %OpenApiSpex.Schema{
    type: :object,
    properties: %{
      id: %OpenApiSpex.Schema{type: :string, format: :uuid},
      email: %OpenApiSpex.Schema{type: :string},
      role: %OpenApiSpex.Schema{type: :string},
      status: %OpenApiSpex.Schema{type: :string}
    }
  }

  @error %OpenApiSpex.Schema{
    type: :object,
    properties: %{error: %OpenApiSpex.Schema{type: :string}}
  }

  operation(:index,
    summary: "List workspace members",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: %{
      200 =>
        {"Members", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{members: %OpenApiSpex.Schema{type: :array, items: @member}}
         }},
      403 => {"Not an admin", "application/json", @error}
    }
  )

  operation(:add,
    summary: "Add workspace member",
    description: "Adds an existing user by email to the workspace with the given role.",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Member params", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:email, :role],
         properties: %{
           email: %OpenApiSpex.Schema{type: :string},
           role: %OpenApiSpex.Schema{type: :string, enum: ["admin", "member"]}
         }
       }},
    responses: %{
      201 => {"Added", "application/json", @member},
      403 => {"Not an admin", "application/json", @error},
      404 => {"User not found", "application/json", @error},
      422 => {"Validation error", "application/json", @error}
    }
  )

  operation(:update_role,
    summary: "Change member role",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      user_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Role", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:role],
         properties: %{role: %OpenApiSpex.Schema{type: :string, enum: ["admin", "member"]}}
       }},
    responses: %{
      200 => {"Updated", "application/json", @member},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Member not found", "application/json", @error},
      409 => {"Last admin", "application/json", @error}
    }
  )

  operation(:remove,
    summary: "Remove workspace member",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      user_id: [in: :path, type: :string, required: true]
    ],
    responses: %{
      204 => {"Removed", nil, nil},
      403 => {"Not an admin", "application/json", @error},
      404 => {"Member not found", "application/json", @error},
      409 => {"Last admin", "application/json", @error}
    }
  )

  def index(conn, %{"workspace_id" => workspace_id}) do
    members = Workspaces.list_members(workspace_id)
    json(conn, %{members: members})
  end

  def add(conn, %{"workspace_id" => workspace_id, "email" => email, "role" => role}) do
    email_downcased = String.downcase(email)

    case Repo.get_by(IssuerAccount, email: email_downcased) do
      nil ->
        conn |> put_status(404) |> json(%{error: "user_not_found"})

      %IssuerAccount{id: user_id, email: user_email} ->
        case Workspaces.add_member(workspace_id, user_id, role) do
          {:ok, _} ->
            conn
            |> put_status(201)
            |> json(%{id: user_id, email: user_email, role: role, status: "active"})

          {:error, %Ecto.Changeset{} = cs} ->
            conn
            |> put_status(422)
            |> json(%{error: "validation_error", details: changeset_errors(cs)})
        end
    end
  end

  def update_role(conn, %{
        "workspace_id" => workspace_id,
        "user_id" => user_id,
        "role" => role
      }) do
    case Workspaces.update_member_role(workspace_id, user_id, role) do
      {:ok, _member} ->
        case Repo.get(IssuerAccount, user_id) do
          nil ->
            conn |> put_status(404) |> json(%{error: "user_not_found"})

          %{email: email} ->
            json(conn, %{id: user_id, email: email, role: role, status: "active"})
        end

      {:error, :not_a_member} ->
        conn |> put_status(404) |> json(%{error: "member_not_found"})

      {:error, :last_admin} ->
        conn |> put_status(409) |> json(%{error: "last_admin"})

      {:error, %Ecto.Changeset{} = cs} ->
        conn
        |> put_status(422)
        |> json(%{error: "validation_error", details: changeset_errors(cs)})
    end
  end

  def remove(conn, %{"workspace_id" => workspace_id, "user_id" => user_id}) do
    case Workspaces.remove_member(workspace_id, user_id) do
      {:ok, _} -> conn |> put_status(204) |> text("")
      {:error, :not_a_member} -> conn |> put_status(404) |> json(%{error: "member_not_found"})
      {:error, :last_admin} -> conn |> put_status(409) |> json(%{error: "last_admin"})
    end
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
