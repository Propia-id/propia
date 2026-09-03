defmodule SovraWeb.Plugs.ApiKeyPlug do
  @moduledoc """
  Authenticates server-to-server requests via a workspace API key.

  Expects `Authorization: Bearer sovra_sk_...` (case-sensitive scheme). Looks
  up the key's SHA-256 hash in `workspace_api_keys`; rejects unknown, malformed,
  or revoked keys with 401. On success assigns `:current_workspace_id` (the
  owning workspace's UUID), `:current_api_key_id`, and
  `:current_auth_method`. Also fire-and-forgets a `last_used_at` update so
  operators can triage leaks.
  """

  use Sovra.Log

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  alias Sovra.Workspaces.ApiKeys

  def init(opts), do: opts

  def call(conn, _opts) do
    with {:ok, token} <- bearer_token(conn),
         {:ok, key} <- ApiKeys.find_active_by_plaintext(token) do
      ApiKeys.touch_last_used(key.id)

      Log.put_context(
        workspace_id: key.workspace_id,
        api_key_id: key.id,
        auth_method: :api_key
      )

      conn
      |> assign(:current_workspace_id, key.workspace_id)
      |> assign(:current_api_key_id, key.id)
      |> assign(:current_auth_method, :api_key)
    else
      {:error, reason} ->
        # A 401 with no log line makes "our API key stopped working" impossible
        # to answer, and hides key-guessing entirely. The key itself is never
        # logged: the reason plus the caller's IP fingerprint is what triages.
        Log.event(:warning, "API key rejected",
          event: "auth.api_key.rejected",
          reason: reason,
          path: conn.request_path,
          ip: client_ip(conn)
        )

        conn |> put_status(401) |> json(%{error: "invalid_api_key"}) |> halt()
    end
  end

  # `find_active_by_plaintext/1` collapses unknown, malformed and revoked into
  # one `:invalid`, so the reason here separates "no credential was presented"
  # from "a credential was presented and refused" — the difference between a
  # misconfigured client and someone trying keys.
  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, token}
      [] -> {:error, :missing}
      _ -> {:error, :malformed_header}
    end
  end

  defp client_ip(conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()
end
