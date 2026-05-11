defmodule SovraWeb.DashboardApiSpec do
  @moduledoc """
  OpenAPI document for the staff-facing dashboard. Paths served: `/dashboard/*`.
  """

  alias OpenApiSpex.{Components, Info, OpenApi, SecurityScheme, Server}
  alias SovraWeb.OpenApiHelpers

  @behaviour OpenApi

  @impl OpenApi
  def spec do
    %OpenApi{
      info: %Info{
        title: "Sovra Dashboard API",
        version: "1.0.0",
        description:
          "Staff-facing dashboard endpoints. Authenticated with an HTTP-only " <>
            "session cookie minted by `POST /dashboard/auth/login` (or the " <>
            "registration / refresh / SSO flows under `/dashboard/auth/*`)."
      },
      servers: [%Server{url: "http://localhost:4000"}],
      paths: OpenApiHelpers.paths_with_prefix(SovraWeb.Router, "/dashboard/"),
      components: %Components{
        securitySchemes: %{
          "SessionCookie" => %SecurityScheme{
            type: "apiKey",
            in: "cookie",
            name: "session",
            description:
              "HTTP-only session cookie. Minted by the bootstrap endpoints " <>
                "under `/dashboard/auth/*` (login, register, refresh)."
          }
        }
      },
      security: [%{"SessionCookie" => []}]
    }
    |> OpenApiSpex.resolve_schema_modules()
  end
end
