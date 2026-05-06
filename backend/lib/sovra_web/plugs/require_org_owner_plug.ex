defmodule SovraWeb.Plugs.RequireOrgOwnerPlug do
  @moduledoc """
  Restricts access to organization endpoints to the `owner` role.
  Must be used after `UserSessionPlug`. Does NOT bypass for platform
  super-admins — Sovra admins must be the org owner to act.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Organizations

  def init(opts), do: opts

  def call(conn, _opts) do
    with %{user_id: user_id} <- conn.assigns[:current_user],
         org_id when is_binary(org_id) <- conn.path_params["org_id"] || conn.params["org_id"],
         {:ok, "owner"} <- Organizations.member_role(org_id, user_id) do
      assign(conn, :current_org_role, "owner")
    else
      _ ->
        conn |> put_status(403) |> json(%{error: "org_owner_required"}) |> halt()
    end
  end
end
