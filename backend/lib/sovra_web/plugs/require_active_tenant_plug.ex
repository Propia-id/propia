defmodule SovraWeb.Plugs.RequireActiveTenantPlug do
  @moduledoc """
  Refuses a request whose workspace, or that workspace's organization, is not
  active. Answers 403 with `workspace_inactive`, `organization_inactive`,
  `workspace_not_found`, or `no_workspace` for a session that has none.

  Authentication proves the credential, not that the tenant behind it may
  still operate: deactivating an organization revokes none of its API keys
  and ends none of its members' sessions. Most of the actions behind these
  routes checked only that the workspace was provisioned, so a deactivated
  tenant could still create schemas and offers and revoke credentials.

  Reads the `:current_workspace_id` that `ApiKeyPlug` and `UserSessionPlug`
  both assign, so an API key and a dashboard session pass the same check.
  Must run after them, and after `RequireWorkspaceAdminPlug` where both
  apply: that plug can re-point `:current_workspace_id`, and the workspace
  checked must be the one the action will use.

  Only requests the tenant makes pass through here. A context function also
  reached from elsewhere — a wallet claiming an offer, a background job —
  still has to check for itself.
  """

  use Sovra.Log

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Workspaces

  def init(opts), do: opts

  def call(conn, _opts) do
    with workspace_id when is_binary(workspace_id) <-
           conn.assigns[:current_workspace_id] || {:error, :no_workspace},
         {:ok, _workspace} <- Workspaces.get_active_workspace(workspace_id) do
      conn
    else
      {:error, reason} -> deny(conn, reason)
    end
  end

  defp deny(conn, reason) do
    Log.event(:warning, "active tenant required",
      event: "authz.denied",
      reason: reason,
      path: conn.request_path
    )

    conn |> put_status(403) |> json(%{error: to_string(reason)}) |> halt()
  end
end
