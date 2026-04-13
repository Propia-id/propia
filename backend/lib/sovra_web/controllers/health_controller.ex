defmodule SovraWeb.HealthController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  tags(["Health"])

  operation(:index,
    summary: "Health check",
    responses: %{
      200 =>
        {"Health status", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{status: %OpenApiSpex.Schema{type: :string, example: "ok"}}
         }}
    }
  )

  def index(conn, _params) do
    json(conn, %{status: "ok"})
  end
end
