# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :sovra,
  env: config_env(),
  ecto_repos: [Sovra.Repo],
  generators: [timestamp_type: :utc_datetime],
  key_store: Sovra.Crypto.KmsKeyStore,
  hmac_key_store: Sovra.Crypto.DatabaseHmacStore,
  auth_provider: Sovra.Auth.GoogleAuthProvider,
  session_secret: "dev-only-secret-must-be-at-least-32-bytes-long!",
  issuer: [base_url: System.get_env("ISSUER_BASE_URL", "http://localhost:4000")],
  ethereum: [
    rpc_url: "http://127.0.0.1:1729",
    chain_id: 65_536_999,
    admin_private_key: nil,
    did_registry_address: nil,
    issuer_registry_address: nil
  ]

config :sovra, :quarkid_resolver,
  base_url: "https://node.sovra.io/resolve/",
  request_timeout_ms: 5_000,
  doc_cache_ttl_s: 300,
  negative_cache_ttl_s: 30

# Configure the endpoint
config :sovra, SovraWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [json: SovraWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Sovra.PubSub,
  live_view: [signing_salt: "3pH4iC/3"]

# Configure Elixir's Logger.
#
# `metadata:` governs the console/journald formatter ONLY. New Relic receives
# every Logger metadata key regardless of this list — NewRelic.LogsInContext
# reads `log.meta` directly — so this is about what a human tailing logs sees,
# not about what is queryable in NRDB. Keys come from Sovra.Log.put_context/1
# (set in the auth plugs) and from Sovra.Log.event/3 call sites.
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [
    :request_id,
    :event,
    :org_id,
    :workspace_id,
    :user_id,
    :api_key_id,
    :auth_method,
    :email_fp,
    :email,
    :email_domain,
    :ip_fp,
    :ip,
    :sovra_address,
    :credential_id,
    :verification_id,
    :delivery_id,
    :document_id,
    :tx_hash,
    :op,
    :stage,
    :step,
    :did,
    :reason,
    :oban_job_id
  ]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Hammer rate limiter
config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 300_000, cleanup_interval_ms: 60_000]}

# Bcrypt — pin the work factor explicitly so a future library default change
# doesn't silently alter password hashing cost. log_rounds: 12 is bcrypt_elixir's
# current default (~250ms per hash on modern hardware).
config :bcrypt_elixir, log_rounds: 12

# Oban job runner (webhooks, mailers, verification housekeeping)
config :sovra, Oban,
  repo: Sovra.Repo,
  queues: [webhooks: 10, mailers: 10, verification: 1, provisioning: 5],
  plugins: [
    {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 7},
    {Oban.Plugins.Cron,
     crontab: [
       {"* * * * *", Sovra.Verification.ExpiredSessionsSweeper}
     ]}
  ]

# Mailer (Swoosh). Local adapter in dev (preview at /dev/mailbox), Test in
# test, Postmark in prod (runtime.exs, from POSTMARK_API_KEY).
config :sovra, Sovra.Mailer, adapter: Swoosh.Adapters.Local

# Local/Test adapters don't talk HTTP. Prod switches this to
# Swoosh.ApiClient.Req for the Postmark adapter.
config :swoosh, :api_client, false

# Sender for transactional email. Must be a verified sender on the Postmark
# account in prod (EMAIL_FROM_* env vars override it).
config :sovra, :emails, from: {"Sovra", "no-reply@sovra.io"}

# Frontend URL used when building reset-password links etc.
config :sovra,
       :issuer_frontend_url,
       System.get_env("ISSUER_FRONTEND_URL", "http://localhost:5173")

# Self-service organization creation (`POST /dashboard/organizations`).
# DISABLED by default until per-account quotas exist; registration already
# provisions one organization plus a workspace.
# ORGANIZATION_CREATION_ENABLED=true in runtime.exs re-opens it per deployment.
config :sovra, :organization_creation_enabled, false

# Self-service registration (`POST /dashboard/auth/register`), the other path
# that creates an organization — it provisions user + org + owner membership +
# workspace in one transaction, and the workspace then provisions keys, a DID
# and an on-chain issuer registration. Enabled here so dev and the test suite
# can sign up freely; REGISTRATION_ENABLED=false in runtime.exs is the kill
# switch, and deployments set it explicitly (see api_deploy.yaml).
# Only gates NEW accounts: existing users keep logging in either way, and the
# admin issuer-account endpoint keeps creating them.
config :sovra, :registration_enabled, true

# CORS — the allow-list is NOT configured here. SovraWeb.Plugs.Cors passes
# `origin` per request from SovraWeb.AllowedOrigins, because anything set in
# config is captured when the endpoint's pipeline is compiled and would ignore
# the runtime ISSUER_FRONTEND_URL.
config :cors_plug,
  credentials: true,
  max_age: 86_400

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
