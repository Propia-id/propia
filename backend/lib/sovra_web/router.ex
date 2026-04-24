defmodule SovraWeb.Router do
  use SovraWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :guardian_session do
    plug SovraWeb.Plugs.SessionPlug
  end

  pipeline :fresh_guardian_session do
    plug SovraWeb.Plugs.SessionPlug, max_age: 300
  end

  pipeline :issuer_session do
    plug SovraWeb.Plugs.IssuerSessionPlug
  end

  pipeline :token_rate_limited do
    plug SovraWeb.Plugs.RateLimitPlug, max_requests: 10, window_ms: 60_000
  end

  pipeline :auth_rate_limited do
    plug SovraWeb.Plugs.RateLimitPlug, max_requests: 5, window_ms: 60_000
  end

  pipeline :require_admin do
    plug SovraWeb.Plugs.RequireAdminPlug
  end

  pipeline :require_org_admin do
    plug SovraWeb.Plugs.RequireOrgAdminPlug
  end

  pipeline :require_org_owner do
    plug SovraWeb.Plugs.RequireOrgOwnerPlug
  end

  # OpenAPI spec & Swagger UI
  scope "/api" do
    pipe_through :api
    get "/openapi", OpenApiSpex.Plug.RenderSpec, []
  end

  if Application.compile_env(:sovra, :dev_routes) do
    scope "/dev" do
      get "/swaggerui", OpenApiSpex.Plug.SwaggerUI, path: "/api/openapi"
    end
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
    get "/.well-known/openid-credential-issuer/:issuer_id", MetadataController, :show_by_id
  end

  # Issuer API (OID4VCI)
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through :api

    post "/credential-offer", CredentialController, :offer
    post "/authorize", CredentialController, :authorize
    post "/credential", CredentialController, :issue
    get "/metadata", MetadataController, :show
    get "/metadata/:issuer_id", MetadataController, :show_by_id
  end

  # Token endpoint with rate limiting
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through [:api, :token_rate_limited]

    post "/token", CredentialController, :token
  end

  # Issuer auth (public, rate limited)
  scope "/api/v1/issuer/auth", SovraWeb.Issuer do
    pipe_through [:api, :auth_rate_limited]

    post "/login", AuthController, :login
    post "/logout", AuthController, :logout
  end

  # Issuer admin API (authenticated)
  scope "/api/v1/issuer/admin", SovraWeb.Issuer do
    pipe_through [:api, :issuer_session]

    get "/profile", AdminController, :get_issuer
    post "/schemas", AdminController, :create_schema
    get "/schemas", AdminController, :list_schemas
    delete "/schemas/:id", AdminController, :delete_schema
    post "/offers", AdminController, :create_offer
    get "/offers", AdminController, :list_offers
    get "/credentials", AdminController, :list_issued_credentials
    post "/credentials/:id/revoke", AdminController, :revoke_credential
    post "/credentials/:id/suspend", AdminController, :suspend_credential
    post "/credentials/:id/unsuspend", AdminController, :unsuspend_credential
  end

  # Super-admin API (admin role required)
  scope "/api/v1/issuer/admin", SovraWeb.Issuer do
    pipe_through [:api, :issuer_session, :require_admin]

    get "/issuers", AdminController, :list_issuers
    post "/issuers", AdminController, :create_issuer_account
  end

  # Organizations API (authenticated; any member can read their orgs)
  scope "/api/v1/organizations", SovraWeb.Organizations do
    pipe_through [:api, :issuer_session]

    post "/", OrganizationController, :create
    get "/", OrganizationController, :index
    get "/:org_id", OrganizationController, :show
  end

  # Organization admin operations (owner or admin)
  scope "/api/v1/organizations", SovraWeb.Organizations do
    pipe_through [:api, :issuer_session, :require_org_admin]

    patch "/:org_id", OrganizationController, :update
    get "/:org_id/members", OrganizationController, :list_members
  end

  # Organization owner-only operations
  scope "/api/v1/organizations", SovraWeb.Organizations do
    pipe_through [:api, :issuer_session, :require_org_owner]

    post "/:org_id/deactivate", OrganizationController, :deactivate
  end

  # Verification API
  scope "/api/v1/verify", SovraWeb.Verify do
    pipe_through :api

    post "/presentation", PresentationController, :verify
    get "/did/:did", PresentationController, :resolve_did
  end

  # Status list API (public, cacheable)
  scope "/api/v1/status", SovraWeb.Verify do
    pipe_through :api

    get "/:issuer_did/:purpose", StatusListController, :show
  end

  # Holder onboarding & auth (public)
  scope "/api/v1/holder", SovraWeb.Guardian do
    pipe_through :api

    post "/onboard", OnboardController, :onboard
    post "/auth", AuthController, :auth
    post "/auth/callback", AuthController, :callback
  end

  # Recovery operations (require fresh auth — token issued within last 5 minutes)
  scope "/api/v1/recovery", SovraWeb.Guardian do
    pipe_through [:api, :fresh_guardian_session]

    post "/rotate-key", RotateController, :rotate
    post "/initiate", RecoveryController, :initiate_recovery
    post "/finalize", RecoveryController, :finalize
  end
end
