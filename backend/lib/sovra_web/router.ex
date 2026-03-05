defmodule SovraWeb.Router do
  use SovraWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :cosigner_session do
    plug SovraWeb.Plugs.SessionPlug
  end

  # Health check
  scope "/", SovraWeb do
    pipe_through :api
    get "/health", HealthController, :index
  end

  # Issuer metadata (well-known)
  scope "/", SovraWeb.Issuer do
    pipe_through :api
    get "/.well-known/openid-credential-issuer", MetadataController, :show
  end

  # Issuer API (OID4VCI)
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through :api

    post "/credential-offer", CredentialController, :offer
    post "/authorize", CredentialController, :authorize
    post "/token", CredentialController, :token
    post "/credential", CredentialController, :issue
    get "/metadata", MetadataController, :show
  end

  # Verification API
  scope "/api/v1/verify", SovraWeb.Verify do
    pipe_through :api

    post "/presentation", PresentationController, :verify
    get "/did/:did", PresentationController, :resolve_did
  end

  # Co-signing API (public)
  scope "/api/v1/cosigner", SovraWeb.Cosigner do
    pipe_through :api

    post "/onboard", OnboardController, :onboard
    post "/auth", AuthController, :auth
    post "/auth/callback", AuthController, :callback
  end

  # Co-signing API (authenticated)
  scope "/api/v1/cosigner", SovraWeb.Cosigner do
    pipe_through [:api, :cosigner_session]

    post "/cosign", SignController, :sign
    post "/rotate-server-key", RotateController, :rotate
    post "/initiate-recovery", RecoveryController, :initiate_recovery
  end
end
