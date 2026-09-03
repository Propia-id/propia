defmodule SovraWeb.Plugs.RequireWorkspaceAdminPlug do
  @moduledoc """
  Restricts access to workspace endpoints to members with role `admin`.
  Must run after `UserSessionPlug`. Does **not** bypass for platform
  super-admins or org admins — workspace membership with role `admin` is
  required explicitly.

  Accepts the workspace id from either the `:workspace_id` path parameter or
  (for endpoints gated by JWT with no path workspace — e.g. credential
  revoke/suspend) the session's `:current_workspace_id` assign.
  """

  use Sovra.Log

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Workspaces

  def init(opts), do: opts

  def call(conn, _opts) do
    # Four different failures used to collapse into one 403 through a single
    # `with/else`, so the log would have said no more than the status code.
    # Each is tagged instead: no session, no resolvable workspace, not a
    # member, or a member without the role.
    with %{user_id: user_id} <- conn.assigns[:current_user] || {:error, :no_session},
         workspace_id when is_binary(workspace_id) <-
           resolve_workspace_id(conn) || {:error, :no_workspace_id},
         {:ok, "admin"} <- Workspaces.member_role(workspace_id, user_id) do
      Log.put_context(workspace_id: workspace_id)

      conn
      |> assign(:current_workspace_id, workspace_id)
      |> assign(:current_workspace_role, "admin")
    else
      {:error, reason} -> deny(conn, reason, nil)
      {:ok, role} -> deny(conn, :insufficient_role, role)
      # A params value can be any shape a client sends — `?workspace_id[]=1`
      # arrives as a list — and reaching the else with an unmatched term used
      # to raise WithClauseError, turning a 403 into a 500. Tagging the
      # reasons must not narrow what the clause accepts.
      _other -> deny(conn, :malformed_workspace_id, nil)
    end
  end

  defp deny(conn, reason, actual_role) do
    Log.event(:warning, "workspace admin required",
      event: "authz.denied",
      reason: reason,
      required_role: "workspace_admin",
      actual_role: actual_role,
      path: conn.request_path
    )

    conn |> put_status(403) |> json(%{error: "workspace_admin_required"}) |> halt()
  end

  defp resolve_workspace_id(conn) do
    conn.path_params["workspace_id"] ||
      conn.params["workspace_id"] ||
      conn.assigns[:current_workspace_id]
  end
end
