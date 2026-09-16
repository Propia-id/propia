defmodule SovraWeb.Router do
  use SovraWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  # The only route that answers with HTML. Everything else here is JSON.
  pipeline :document_page do
    plug :accepts, ["html"]
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

  # Looser than :auth_rate_limited, which is too tight here: entering the code
  # can legitimately take a few tries before the right one lands.
  pipeline :invitation_rate_limited do
    plug SovraWeb.Plugs.RateLimitPlug, max_requests: 20, window_ms: 60_000
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

  pipeline :put_dashboard_api_spec do
    plug OpenApiSpex.Plug.PutApiSpec, module: SovraWeb.DashboardApiSpec
  end

  pipeline :put_wallet_api_spec do
    plug OpenApiSpex.Plug.PutApiSpec, module: SovraWeb.WalletApiSpec
  end

  pipeline :put_integration_api_spec do
    plug OpenApiSpex.Plug.PutApiSpec, module: SovraWeb.ApiSpec
  end

  # OpenAPI specs (one per audience)
  scope "/openapi" do
    pipe_through [:api, :put_dashboard_api_spec]
    get "/dashboard", OpenApiSpex.Plug.RenderSpec, []
  end

  scope "/openapi" do
    pipe_through [:api, :put_wallet_api_spec]
    get "/wallet", OpenApiSpex.Plug.RenderSpec, []
  end

  scope "/openapi" do
    pipe_through [:api, :put_integration_api_spec]
    get "/api", OpenApiSpex.Plug.RenderSpec, []
  end

  # Legacy /api/openapi → integrator spec (301)
  scope "/api", SovraWeb do
    pipe_through :api
    get "/openapi", LegacyOpenApiController, :redirect_to_api_spec
  end

  if Application.compile_env(:sovra, :dev_routes) do
    scope "/dev" do
      get "/swaggerui/dashboard", OpenApiSpex.Plug.SwaggerUI, path: "/openapi/dashboard"
      get "/swaggerui/wallet", OpenApiSpex.Plug.SwaggerUI, path: "/openapi/wallet"
      get "/swaggerui/api", OpenApiSpex.Plug.SwaggerUI, path: "/openapi/api"
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end

  # Probes — no auth. `/health` is liveness only and must stay cheap: the
  # Cloudflare tunnel and the deploy gate hit it. `/ready` is the dependency
  # check; it reads a cached snapshot, so it is just as cheap to serve. Both are
  # excluded from `force_ssl` in prod.exs so an external plain-HTTP probe gets
  # an answer instead of a 301.
  scope "/", SovraWeb do
    pipe_through :api
    get "/health", HealthController, :index
    get "/ready", HealthController, :ready
  end

  # Issuer metadata (well-known)
  #
  # Issuer metadata (OID4VCI 1.0 §11.2) uses path concatenation: the path
  # component of the Credential Issuer Identifier comes *before* /.well-known/...
  #
  # AS metadata: when the issuer identifier has a path component, OID4VCI 1.0
  # §11.2.3 requires *both* discovery forms — RFC 8414 §3 insertion (well-known
  # between host and path) AND path concatenation (well-known appended after
  # the path). Wallets may use either, so we serve both.
  scope "/", SovraWeb.Issuer do
    pipe_through :api

    get "/:workspace_did/.well-known/openid-credential-issuer",
        MetadataController,
        :show_by_id

    get "/.well-known/oauth-authorization-server/:workspace_did",
        AuthServerMetadataController,
        :show_by_id

    get "/:workspace_did/.well-known/oauth-authorization-server",
        AuthServerMetadataController,
        :show_by_id
  end

  # ── /dashboard — staff session-authenticated + bootstrap ──────────────

  # Bootstrap (session-minting). Rate-limited + Origin allow-list.
  scope "/dashboard/auth", SovraWeb do
    pipe_through [:api, :auth_rate_limited, :auth_origin_check]

    post "/register", AuthController, :register
    post "/login", AuthController, :login
    post "/logout", AuthController, :logout
    post "/refresh", AuthController, :refresh
    post "/password/reset-request", AuthController, :password_reset_request
    post "/password/reset", AuthController, :password_reset_confirm
  end

  # Redeeming an invitation. Public: the token in the body is the authorization.
  # Self-service registration is closed, so this is the way in.
  scope "/dashboard/auth/invitations", SovraWeb.Invitations do
    pipe_through [:api, :invitation_rate_limited, :auth_origin_check]

    post "/lookup", InvitationController, :lookup
    post "/request-code", InvitationController, :request_code
    post "/accept", InvitationController, :accept
  end

  # Issuing invitations. Authorizing a new issuer is Sovra's call.
  scope "/dashboard/invitations", SovraWeb.Invitations do
    pipe_through [:api, :user_session, :require_admin]

    post "/", AdminInvitationController, :create
    get "/", AdminInvitationController, :index
    delete "/:id", AdminInvitationController, :revoke
  end

  # Issuer admin
  scope "/dashboard/issuer", SovraWeb.Issuer do
    pipe_through [:api, :user_session]

    get "/profile", AdminController, :get_issuer
    post "/schemas", AdminController, :create_schema
    get "/schemas", AdminController, :list_schemas
    put "/schemas/:schema_id", AdminController, :revise_schema
    delete "/schemas/:id", AdminController, :delete_schema
    get "/schemas/:schema_id/design", AdminController, :get_design
    put "/schemas/:schema_id/design", AdminController, :upsert_design
    delete "/schemas/:schema_id/design", AdminController, :delete_design
    put "/schemas/:schema_id/layout", AdminController, :update_layout
    post "/offers", OfferController, :create
    get "/offers", AdminController, :list_offers
    get "/credentials", AdminController, :list_issued_credentials
    get "/credentials/:id", AdminController, :show_issued_credential
    post "/documents", DocumentController, :create
    get "/documents", DocumentController, :index
    put "/documents/:id/visibility/:visibility", DocumentController, :update_visibility
  end

  # Verification sessions on the dashboard (JWT session) — reuses the
  # workspace-scoped controller actions also exposed under /api/v1/verifier/.
  scope "/dashboard/issuer", SovraWeb.Verifier do
    pipe_through [:api, :user_session]

    post "/verifications", VerificationController, :create
    get "/verifications", VerificationController, :index
    get "/verifications/:id", VerificationController, :show
  end

  # Admin-only credential status changes (workspace admin required)
  scope "/dashboard/issuer", SovraWeb.Issuer do
    pipe_through [:api, :user_session, :require_workspace_admin]

    put "/credentials/:id/status/:status", AdminController, :update_credential_status
  end

  # Super-admin (admin role required)
  scope "/dashboard/issuer", SovraWeb.Issuer do
    pipe_through [:api, :user_session, :require_admin]

    get "/issuers", AdminController, :list_issuers
    post "/issuers", AdminController, :create_issuer_account
  end

  # Organizations
  scope "/dashboard/organizations", SovraWeb.Organizations do
    pipe_through [:api, :user_session]

    post "/", OrganizationController, :create
    get "/", OrganizationController, :index
    get "/:org_id", OrganizationController, :show
  end

  scope "/dashboard/organizations", SovraWeb.Organizations do
    pipe_through [:api, :user_session, :require_org_admin]

    patch "/:org_id", OrganizationController, :update
    get "/:org_id/members", OrganizationController, :list_members
  end

  scope "/dashboard/organizations", SovraWeb.Organizations do
    pipe_through [:api, :user_session, :require_org_owner]

    post "/:org_id/deactivate", OrganizationController, :deactivate
  end

  # Org-scoped workspace collection ops (admin/owner only)
  scope "/dashboard/organizations/:org_id/workspaces", SovraWeb.Workspaces do
    pipe_through [:api, :user_session, :require_org_admin]

    get "/", WorkspaceController, :list
    post "/", WorkspaceController, :create

    post "/:workspace_id/retry_provisioning",
         WorkspaceController,
         :retry_provisioning
  end

  # Workspace reads (any member)
  scope "/dashboard/workspaces", SovraWeb.Workspaces do
    pipe_through [:api, :user_session]

    get "/", WorkspaceController, :index
    get "/:workspace_id", WorkspaceController, :show
    post "/:workspace_id/switch", WorkspaceController, :switch
  end

  # Workspace admin operations (workspace admin required)
  scope "/dashboard/workspaces", SovraWeb.Workspaces do
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

  # ── /wallet — wallet-facing protocol + holder auth + recovery ─────────

  # OID4VCI holder flow (public — protocol-authenticated)
  scope "/wallet/issuer", SovraWeb.Issuer do
    pipe_through :api

    post "/authorize", CredentialController, :authorize
    post "/credential", CredentialController, :issue
    get "/metadata/:workspace_did", MetadataController, :show_by_id

    get "/credential-manifests", ManifestController, :index
    get "/credential-manifests/:schema_id", ManifestController, :show
  end

  # Token endpoint with rate limiting
  scope "/wallet/issuer", SovraWeb.Issuer do
    pipe_through [:api, :token_rate_limited]

    post "/token", CredentialController, :token
  end

  # OID4VP — wallet-facing verification endpoints
  scope "/wallet/verifier", SovraWeb.Verify do
    pipe_through :api

    post "/presentation", PresentationController, :verify
    get "/did/:did", PresentationController, :resolve_did
  end

  # Wallet direct_post submission (rate-limited)
  scope "/wallet/verifier", SovraWeb.Verify do
    pipe_through [:api, :offer_rate_limited]

    post "/direct_post/:session_id", DirectPostController, :submit
  end

  # Pass-by-reference request object. Outside :api on purpose: wallets ask for
  # `application/oauth-authz-req+jwt`, which `plug :accepts, ["json"]` 406s.
  scope "/wallet/verifier", SovraWeb.Verify do
    pipe_through :offer_rate_limited

    get "/request/:session_id", RequestController, :show
  end

  # Holder onboarding & login (public)
  scope "/wallet/auth", SovraWeb.Guardian do
    pipe_through :api

    post "/onboard", OnboardController, :onboard
    post "/login", AuthController, :login
    post "/callback", AuthController, :callback
  end

  # Recovery operations (require fresh holder session — token issued within
  # the last 5 minutes)
  scope "/wallet/recovery", SovraWeb.Guardian do
    pipe_through [:api, :fresh_guardian_session]

    post "/rotate-key", RotateController, :rotate
    post "/initiate", RecoveryController, :initiate_recovery
    post "/finalize", RecoveryController, :finalize
  end

  # ── /api/v1 — server-to-server (workspace API key) ────────────────────

  # Credential offer (API-key-gated, issuer-initiated)
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through [:api, :api_key, :offer_rate_limited]

    post "/credential-offer", OfferController, :create
  end

  # Credential lifecycle (workspace API key)
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through [:api, :api_key]

    get "/credentials", AdminController, :list_issued_credentials
    get "/credentials/:id", AdminController, :show_issued_credential
    put "/credentials/:id/status/:status", AdminController, :update_credential_status
  end

  # Signed documents (workspace API key). Schemas and layouts stay on the
  # dashboard, like credential schemas.
  scope "/api/v1/issuer", SovraWeb.Issuer do
    pipe_through [:api, :api_key]

    post "/documents", DocumentController, :create
    get "/documents", DocumentController, :index
    put "/documents/:id/visibility/:visibility", DocumentController, :update_visibility
  end

  # Verifier API (workspace API key — server-to-server, used to start OID4VP
  # sessions)
  scope "/api/v1/verifier", SovraWeb.Verifier do
    pipe_through [:api, :api_key]

    post "/verifications", VerificationController, :create
    get "/verifications", VerificationController, :index
    get "/verifications/:id", VerificationController, :show
  end

  # Status list API (public, cacheable). Path is IMMUTABLE — already-issued
  # VCs embed this URL inside their `status` claim.
  scope "/api/v1/status", SovraWeb.Verify do
    pipe_through :api

    get "/:issuer_did/:purpose", StatusListController, :show
  end

  # Signed documents, public. Serves the credential so a verifier can check it,
  # never a verdict. Holding the id is the authorization.
  scope "/api/v1/documents", SovraWeb.Verify do
    pipe_through :api

    get "/:id", DocumentController, :show
  end

  # The same document, rendered as a page, for a browser or for an agent that
  # wants the document rather than the credential.
  #
  # Under /api/v1 because the dashboard is a single page app served from `/` and
  # owns `/documents` itself: a page route at the root would collide with its tab.
  scope "/api/v1/documents", SovraWeb.Verify do
    pipe_through :document_page

    get "/:id/page", DocumentController, :page
  end
end
