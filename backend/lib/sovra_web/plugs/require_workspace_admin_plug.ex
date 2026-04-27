defmodule SovraWeb.Plugs.RequireWorkspaceAdminPlug do
  @moduledoc """
  Restricts access to workspace endpoints to members with role `admin`.
  Must run after `IssuerSessionPlug`. Does **not** bypass for platform
  super-admins or org admins — workspace membership with role `admin` is
  required explicitly.

  Accepts the workspace id from either the `:workspace_id` path parameter or
  (for endpoints gated by JWT with no path workspace — e.g. credential
  revoke/suspend) the session's `:current_workspace_id` assign.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Workspaces

  def init(opts), do: opts

  def call(conn, _opts) do
    with %{account_id: account_id} <- conn.assigns[:current_issuer_account],
         workspace_id when is_binary(workspace_id) <- resolve_workspace_id(conn),
         {:ok, "admin"} <- Workspaces.member_role(workspace_id, account_id) do
      conn
      |> assign(:current_workspace_id, workspace_id)
      |> assign(:current_workspace_role, "admin")
    else
      _ ->
        conn |> put_status(403) |> json(%{error: "workspace_admin_required"}) |> halt()
    end
  end

  defp resolve_workspace_id(conn) do
    conn.path_params["workspace_id"] ||
      conn.params["workspace_id"] ||
      conn.assigns[:current_workspace_id]
  end
end
