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

  pipeline :user_session do
    plug SovraWeb.Plugs.OriginCheckPlug
    plug SovraWeb.Plugs.UserSessionPlug
  end

  # Public auth routes also need Origin checking on mutations because they
  # set/clear cookies (login/register/logout/refresh).
  pipeline :auth_origin_check do
    plug SovraWeb.Plugs.OriginCheckPlug
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

  pipeline :api_key do
    plug SovraWeb.Plugs.ApiKeyPlug
  end

  pipeline :require_workspace_admin do
    plug SovraWeb.Plugs.RequireWorkspaceAdminPlug
  end

  pipeline :offer_rate_limited do
    plug SovraWeb.Plugs.RateLimitPlug, max_requests: 120, window_ms: 60_000
  end

  # OpenAPI spec & Swagger UI
  scope "/api" do
    pipe_through :api
    get "/openapi", OpenApiSpex.Plug.RenderSpec, []
  end

  if Application.compile_env(:sovra, :dev_routes) do
    scope "/dev" do
      get "/swaggerui", OpenApiSpex.Plug.SwaggerUI, path: "/api/openapi"
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end

  # Health check
  scope "/", SovraWeb do
    pipe_through :api
    get "/health", HealthController, :index
  end

  # Issuer metadata (well-known)
  #
  # The two well-known documents follow different URL-construction rules:
  #   - Issuer metadata (OID4VCI 1.0 §11.2): the path component of the
  #     Credential Issuer Identifier comes *before* /.well-known/...
  #   - AS metadata (RFC 8414 §3): /.well-known/... is inserted *between*
  #     the host and the path component.
  scope "/", SovraWeb.Issuer do
    pipe_through :api

    get "/:workspace_did/.well-known/openid-credential-issuer",
        MetadataController,
        :show_by_id

    get "/.well-known/oauth-authorization-server/:workspace_did",
        AuthServerMetadataController,
        :show_by_id
  end

  # Issuer API (OID4VCI holder flow — public by design)
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through :api

    post "/authorize", CredentialController, :authorize
    post "/credential", CredentialController, :issue
    get "/metadata/:workspace_did", MetadataController, :show_by_id

    get "/credential-manifests", ManifestController, :index
    get "/credential-manifests/:schema_id", ManifestController, :show
  end

  # Credential offer (API-key-gated, server-to-server issuer-initiated flow)
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through [:api, :api_key, :offer_rate_limited]

    post "/credential-offer", OfferController, :create
  end

  # Token endpoint with rate limiting
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through [:api, :token_rate_limited]

    post "/token", CredentialController, :token
  end

  # Public auth endpoints (rate limited + Origin allow-list on mutations)
  scope "/api/v1/auth", SovraWeb do
    pipe_through [:api, :auth_rate_limited, :auth_origin_check]

    post "/register", AuthController, :register
    post "/login", AuthController, :login
    post "/logout", AuthController, :logout
    post "/refresh", AuthController, :refresh
    post "/password/reset-request", AuthController, :password_reset_request
    post "/password/reset", AuthController, :password_reset_confirm
  end

  # Issuer admin API (authenticated)
  scope "/api/v1/issuer/admin", SovraWeb.Issuer do
    pipe_through [:api, :user_session]

    get "/profile", AdminController, :get_issuer
    post "/schemas", AdminController, :create_schema
    get "/schemas", AdminController, :list_schemas
    put "/schemas/:schema_id", AdminController, :revise_schema
    delete "/schemas/:id", AdminController, :delete_schema
    get "/schemas/:schema_id/design", AdminController, :get_design
    put "/schemas/:schema_id/design", AdminController, :upsert_design
    delete "/schemas/:schema_id/design", AdminController, :delete_design
    post "/offers", OfferController, :create
    get "/offers", AdminController, :list_offers
    get "/credentials", AdminController, :list_issued_credentials
    get "/credentials/:id", AdminController, :show_issued_credential
  end

  # Verification listings on the dashboard (JWT session) — reuses the
  # workspace-scoped controller actions also exposed under /api/v1/verifier/.
  scope "/api/v1/issuer/admin", SovraWeb.Verifier do
    pipe_through [:api, :user_session]

    get "/verifications", VerificationController, :index
    get "/verifications/:id", VerificationController, :show
  end

  # Admin-only credential status changes (workspace admin required)
  scope "/api/v1/issuer/admin", SovraWeb.Issuer do
    pipe_through [:api, :user_session, :require_workspace_admin]

    put "/credentials/:id/status/:status", AdminController, :update_credential_status
  end

  # Issuer credential API (workspace API key — server-to-server lifecycle ops).
  # Same controller actions as the dashboard mount above; both pipelines assign
  # `current_workspace_id`, so AdminController is auth-agnostic here.
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through [:api, :api_key]

    get "/credentials", AdminController, :list_issued_credentials
    get "/credentials/:id", AdminController, :show_issued_credential
    put "/credentials/:id/status/:status", AdminController, :update_credential_status
  end

  # Super-admin API (admin role required)
  scope "/api/v1/issuer/admin", SovraWeb.Issuer do
    pipe_through [:api, :user_session, :require_admin]

    get "/issuers", AdminController, :list_issuers
    post "/issuers", AdminController, :create_issuer_account
  end

  # Organizations API (authenticated; any member can read their orgs)
  scope "/api/v1/organizations", SovraWeb.Organizations do
    pipe_through [:api, :user_session]

    post "/", OrganizationController, :create
    get "/", OrganizationController, :index
    get "/:org_id", OrganizationController, :show
  end

  # Organization admin operations (owner or admin)
  scope "/api/v1/organizations", SovraWeb.Organizations do
    pipe_through [:api, :user_session, :require_org_admin]

    patch "/:org_id", OrganizationController, :update
    get "/:org_id/members", OrganizationController, :list_members
  end

  # Organization owner-only operations
  scope "/api/v1/organizations", SovraWeb.Organizations do
    pipe_through [:api, :user_session, :require_org_owner]

    post "/:org_id/deactivate", OrganizationController, :deactivate
  end

  # Org-scoped workspace collection ops (admin/owner only)
  scope "/api/v1/organizations/:org_id/workspaces", SovraWeb.Workspaces do
    pipe_through [:api, :user_session, :require_org_admin]

    get "/", WorkspaceController, :list
    post "/", WorkspaceController, :create
  end

  # Workspace API — any authenticated user (reads for members)
  scope "/api/v1/workspaces", SovraWeb.Workspaces do
    pipe_through [:api, :user_session]

    get "/", WorkspaceController, :index
    get "/:workspace_id", WorkspaceController, :show
    post "/:workspace_id/switch", WorkspaceController, :switch
  end

  # Workspace admin operations (workspace admin required)
  scope "/api/v1/workspaces", SovraWeb.Workspaces do
    pipe_through [:api, :user_session, :require_workspace_admin]

    patch "/:workspace_id", WorkspaceController, :update

    post "/:workspace_id/regenerate_webhook_secret",
         WorkspaceController,
         :regenerate_webhook_secret

    get "/:workspace_id/members", WorkspaceMemberController, :index
    post "/:workspace_id/members", WorkspaceMemberController, :add
    patch "/:workspace_id/members/:user_id", WorkspaceMemberController, :update_role
    delete "/:workspace_id/members/:user_id", WorkspaceMemberController, :remove

    get "/:workspace_id/api_keys", ApiKeyController, :index
    post "/:workspace_id/api_keys", ApiKeyController, :create
    post "/:workspace_id/api_keys/:id/revoke", ApiKeyController, :revoke
  end

  # Verifier API (workspace API key — server-to-server, used to start OID4VP sessions)
  scope "/api/v1/verifier", SovraWeb.Verifier do
    pipe_through [:api, :api_key]

    post "/verifications", VerificationController, :create
    get "/verifications", VerificationController, :index
    get "/verifications/:id", VerificationController, :show
  end

  # Verification API
  scope "/api/v1/verify", SovraWeb.Verify do
    pipe_through :api

    post "/presentation", PresentationController, :verify
    get "/did/:did", PresentationController, :resolve_did
  end

  # Wallet direct_post submission (public, rate-limited)
  scope "/api/v1/verify", SovraWeb.Verify do
    pipe_through [:api, :offer_rate_limited]

    post "/direct_post/:session_id", DirectPostController, :submit
    get "/request/:session_id", RequestController, :show
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
