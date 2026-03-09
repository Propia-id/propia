defmodule SovraWeb.Relay.SessionController do
  use SovraWeb, :controller

  alias Sovra.Relay.SessionStore

  def create(conn, _params) do
    session_id = SessionStore.create()
    base = "#{conn.scheme}://#{conn.host}:#{conn.port}/api/v1/relay/sessions/#{session_id}"

    conn
    |> put_status(:created)
    |> json(%{
      sessionId: session_id,
      requestUri: "#{base}/request",
      responseUri: "#{base}/response"
    })
  end

  def upload_request(conn, %{"id" => id}) do
    request = conn.body_params["request"]

    case SessionStore.put_request(id, request) do
      :ok -> send_resp(conn, :no_content, "")
      :not_found -> send_resp(conn, :not_found, "")
    end
  end

  def get_request(conn, %{"id" => id}) do
    case SessionStore.get_request(id) do
      {:ok, nil} -> send_resp(conn, :no_content, "")
      {:ok, request} -> json(conn, %{request: request})
      :not_found -> send_resp(conn, :not_found, "")
    end
  end

  def submit_response(conn, %{"id" => id}) do
    vp_token = conn.body_params["vp_token"]

    case SessionStore.put_response(id, vp_token) do
      :ok -> send_resp(conn, :no_content, "")
      :not_found -> send_resp(conn, :not_found, "")
    end
  end

  def get_response(conn, %{"id" => id}) do
    case SessionStore.get_response(id) do
      {:ok, nil} -> send_resp(conn, :no_content, "")
      {:ok, vp_token} -> json(conn, %{vp_token: vp_token})
      :not_found -> send_resp(conn, :not_found, "")
    end
  end

  def delete_session(conn, %{"id" => id}) do
    SessionStore.delete(id)
    send_resp(conn, :no_content, "")
  end
end
