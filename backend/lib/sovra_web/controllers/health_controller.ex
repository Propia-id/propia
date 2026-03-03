defmodule SovraWeb.HealthController do
  use SovraWeb, :controller

  def index(conn, _params) do
    json(conn, %{status: "ok"})
  end
end
