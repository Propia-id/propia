defmodule SovraWeb.ApiSpec do
  alias OpenApiSpex.{Info, OpenApi, Paths, Server, SecurityScheme, Components}

  @behaviour OpenApi

  @impl OpenApi
  def spec do
    %OpenApi{
      info: %Info{
        title: "Sovra API",
        version: "1.0.0",
        description: "Self-sovereign identity platform implementing OID4VCI credential issuance."
      },
      servers: [%Server{url: "http://localhost:4000"}],
      paths: Paths.from_router(SovraWeb.Router),
      components: %Components{
        securitySchemes: %{
          "IssuerCookieAuth" => %SecurityScheme{
            type: "apiKey",
            in: "cookie",
            name: "issuer_session"
          },
          "BearerAuth" => %SecurityScheme{
            type: "http",
            scheme: "bearer"
          }
        }
      }
    }
    |> OpenApiSpex.resolve_schema_modules()
  end
end
