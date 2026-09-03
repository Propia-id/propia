defmodule SovraWeb.Plugs.RequireOrgAdminPlug do
  @moduledoc """
  Restricts access to organization endpoints to `owner` or `admin` members.
  Must be used after `UserSessionPlug`. Does NOT bypass for platform
  super-admins — Sovra admins must be explicit org members to act on one.
  """

  use Sovra.Log

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Organizations

  def init(opts), do: opts

  def call(conn, _opts) do
    with %{user_id: user_id} <- conn.assigns[:current_user] || {:error, :no_session},
         org_id when is_binary(org_id) <-
           conn.path_params["org_id"] || conn.params["org_id"] || {:error, :no_org_id} do
      case Organizations.member_role(org_id, user_id) do
        {:ok, role} when role in ~w(owner admin) ->
          Log.put_context(org_id: org_id)

          assign(conn, :current_org_role, role)

        {:ok, member_role} ->
          deny(conn, :insufficient_role, member_role, org_id)

        {:error, :not_a_member} ->
          # 404, not 403: an org's existence is not disclosed to non-members.
          deny(conn, :not_a_member, nil, org_id, 404, "organization_not_found")
      end
    else
      {:error, reason} -> deny(conn, reason, nil, nil)
      # `?org_id[]=1` arrives as a list: non-nil, non-binary, and previously a
      # WithClauseError rather than a 403.
      _other -> deny(conn, :malformed_org_id, nil, nil)
    end
  end

  defp deny(conn, reason, actual_role, org_id, status \\ 403, error \\ "org_admin_required") do
    Log.event(:warning, "org admin required",
      event: "authz.denied",
      reason: reason,
      required_role: "org_admin",
      actual_role: actual_role,
      org_id: org_id,
      path: conn.request_path
    )

    conn |> put_status(status) |> json(%{error: error}) |> halt()
  end
end
