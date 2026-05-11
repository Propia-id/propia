defmodule SovraWeb.WalletApiSpec do
  @moduledoc """
  OpenAPI document for the wallet-facing surface. Paths served: `/wallet/*`.

  Covers OID4VCI (`/wallet/issuer/*`), OID4VP (`/wallet/verifier/*`), holder
  onboarding & login (`/wallet/auth/*`), and recovery (`/wallet/recovery/*`).

  Most protocol routes carry no global security scheme because authentication
  is performed via protocol-internal artifacts (DPoP, c_nonce, pre-authorized
  code, request_uri JWT) that aren't expressible as an OpenAPI security
  scheme. Only `/wallet/recovery/*` uses the documented holder-session bearer.
  """

  alias OpenApiSpex.{Components, Info, OpenApi, SecurityScheme, Server}
  alias SovraWeb.OpenApiHelpers

  @behaviour OpenApi

  @impl OpenApi
  def spec do
    %OpenApi{
      info: %Info{
        title: "Sovra Wallet API",
        version: "1.0.0",
        description:
          "Wallet-facing endpoints: OID4VCI issuance, OID4VP verification, " <>
            "holder onboarding and recovery."
      },
      servers: [%Server{url: "http://localhost:4000"}],
      paths: OpenApiHelpers.paths_with_prefix(SovraWeb.Router, "/wallet/"),
      components: %Components{
        securitySchemes: %{
          "HolderSession" => %SecurityScheme{
            type: "http",
            scheme: "bearer",
            description:
              "Holder session token issued by `POST /wallet/auth/login` or " <>
                "`POST /wallet/auth/callback`. Required for `/wallet/recovery/*`."
          }
        }
      }
    }
    |> OpenApiSpex.resolve_schema_modules()
  end
end
