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
  key_store: Sovra.Crypto.VaultKeyStore,
  hmac_key_store: Sovra.Crypto.VaultHmacStore,
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

# Oban job runner (webhook delivery + verification housekeeping)
config :sovra, Oban,
  repo: Sovra.Repo,
  queues: [webhooks: 10, verification: 1],
  plugins: [
    {Oban.Plugins.Pruner, max_age: 60 * 60 * 24 * 7},
    {Oban.Plugins.Cron,
     crontab: [
       {"* * * * *", Sovra.Verification.ExpiredSessionsSweeper}
     ]}
  ]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
