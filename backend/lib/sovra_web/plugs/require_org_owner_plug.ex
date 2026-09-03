defmodule SovraWeb.Plugs.RequireOrgOwnerPlug do
  @moduledoc """
  Restricts access to organization endpoints to the `owner` role.
  Must be used after `UserSessionPlug`. Does NOT bypass for platform
  super-admins — Sovra admins must be the org owner to act.
  """

  use Sovra.Log

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Organizations

  def init(opts), do: opts

  def call(conn, _opts) do
    with %{user_id: user_id} <- conn.assigns[:current_user] || {:error, :no_session},
         org_id when is_binary(org_id) <-
           conn.path_params["org_id"] || conn.params["org_id"] || {:error, :no_org_id},
         {:ok, "owner"} <- Organizations.member_role(org_id, user_id) do
      Log.put_context(org_id: org_id)

      assign(conn, :current_org_role, "owner")
    else
      {:error, :not_a_member} -> deny(conn, :not_a_member, nil)
      {:error, reason} -> deny(conn, reason, nil)
      {:ok, role} -> deny(conn, :insufficient_role, role)
      # `?org_id[]=1` arrives as a list: non-nil, non-binary, and previously a
      # WithClauseError rather than a 403.
      _other -> deny(conn, :malformed_org_id, nil)
    end
  end

  defp deny(conn, reason, actual_role) do
    Log.event(:warning, "org owner required",
      event: "authz.denied",
      reason: reason,
      required_role: "org_owner",
      actual_role: actual_role,
      path: conn.request_path
    )

    conn |> put_status(403) |> json(%{error: "org_owner_required"}) |> halt()
  end
end
