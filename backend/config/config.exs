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

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

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

# Mailer (Swoosh). Local adapter in dev/test; configure SMTP/Resend/etc. in
# runtime.exs for prod.
config :sovra, Sovra.Mailer, adapter: Swoosh.Adapters.Local

config :swoosh, :api_client, false

# Frontend URL used when building reset-password links etc.
config :sovra,
       :issuer_frontend_url,
       System.get_env("ISSUER_FRONTEND_URL", "http://localhost:5173")

# CORS — explicit allow-list for cross-origin requests with credentials.
# In dev we permit the issuer frontend origin and a couple of common alt ports;
# prod is overridden via runtime.exs.
config :cors_plug,
  origin: [System.get_env("ISSUER_FRONTEND_URL", "http://localhost:5173")],
  credentials: true,
  max_age: 86_400

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
