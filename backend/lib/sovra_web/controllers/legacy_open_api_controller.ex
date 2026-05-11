defmodule SovraWeb.LegacyOpenApiController do
  use SovraWeb, :controller

  def redirect_to_api_spec(conn, _params) do
    conn
    |> put_status(:moved_permanently)
    |> redirect(to: "/openapi/api")
  end
end
