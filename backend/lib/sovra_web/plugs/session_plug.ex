defmodule SovraWeb.Plugs.SessionPlug do
  @moduledoc """
  Plug that authenticates co-signing requests via session JWT.
  Expects `Authorization: Bearer <token>` header.

  Options:
    - `:max_age` — if set, requires the token's `iat` to be within this many
      seconds of now (step-up / fresh-auth check). Returns 403 if stale.
  """

  import Plug.Conn
  import Phoenix.Controller, only: [json: 2]

  def init(opts), do: opts

  def call(conn, opts) do
    max_age = Keyword.get(opts, :max_age)

    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, %{sovra_address: address, iat: iat}} <- Sovra.Auth.Session.verify(token),
         :ok <- check_freshness(iat, max_age) do
      assign(conn, :current_holder, %{sovra_address: address})
    else
      [] ->
        conn |> put_status(401) |> json(%{error: "missing_authorization"}) |> halt()

      {:error, :expired} ->
        conn |> put_status(401) |> json(%{error: "session_expired"}) |> halt()

      {:error, :session_not_fresh} ->
        conn |> put_status(403) |> json(%{error: "session_not_fresh"}) |> halt()

      {:error, _} ->
        conn |> put_status(401) |> json(%{error: "invalid_session"}) |> halt()
    end
  end

  defp check_freshness(_iat, nil), do: :ok

  defp check_freshness(iat, max_age) do
    if System.system_time(:second) - iat <= max_age,
      do: :ok,
      else: {:error, :session_not_fresh}
  end
end
