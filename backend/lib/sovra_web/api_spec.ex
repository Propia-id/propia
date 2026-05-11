defmodule SovraWeb.ApiSpec do
  @moduledoc """
  OpenAPI document for the integrator-facing API (workspace API key).

  Paths served: `/api/v1/*` (excluding the public `/api/v1/status/*` endpoint,
  which has no API-key requirement but is included so external monitoring can
  see its shape).
  """

  alias OpenApiSpex.{Components, Info, OpenApi, SecurityScheme, Server}
  alias SovraWeb.OpenApiHelpers

  @behaviour OpenApi

  @impl OpenApi
  def spec do
    %OpenApi{
      info: %Info{
        title: "Sovra API",
        version: "1.0.0",
        description:
          "Server-to-server API for credential issuance and verification. " <>
            "Authenticated with a workspace API key passed as " <>
            "`Authorization: Bearer sovra_sk_...`."
      },
      servers: [%Server{url: "http://localhost:4000"}],
      paths: OpenApiHelpers.paths_with_prefix(SovraWeb.Router, "/api/v1/"),
      components: %Components{
        securitySchemes: %{
          "ApiKeyAuth" => %SecurityScheme{
            type: "http",
            scheme: "bearer",
            description: "Workspace API key. Format: `Bearer sovra_sk_...`."
          }
        }
      },
      security: [%{"ApiKeyAuth" => []}]
    }
    |> OpenApiSpex.resolve_schema_modules()
  end
end
