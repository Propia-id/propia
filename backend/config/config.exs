# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :sovra,
  ecto_repos: [Sovra.Repo],
  generators: [timestamp_type: :utc_datetime],
  key_store: Sovra.Crypto.SoftwareKeyStore,
  auth_provider: Sovra.Auth.GoogleAuthProvider,
  session_secret: "dev-only-secret-must-be-at-least-32-bytes-long!"

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

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
