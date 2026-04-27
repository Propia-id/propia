import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :sovra, Sovra.Repo,
  username: System.get_env("PGUSER", System.get_env("USER")),
  database: "sovra_test#{System.get_env("MIX_TEST_PARTITION")}",
  socket_dir: System.get_env("PGHOST", "/tmp"),
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :sovra, SovraWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "+IpCk7u6d8wD+jABpM9K1t4OkH4v/Oy5/eu0C30Zzt4jnLi0ulGaep4Asz7YMQq4",
  server: false

# Co-signing server test config
config :sovra,
  key_store: Sovra.Crypto.SoftwareKeyStore,
  hmac_key_store: Sovra.Crypto.DatabaseHmacStore,
  auth_provider: Sovra.Auth.MockAuthProvider,
  session_secret: "test-secret-must-be-at-least-32-bytes-long-for-hmac!",
  google_client_id: "test-client-id",
  google_client_secret: "test-client-secret",
  google_redirect_uri: "http://localhost:4002/api/v1/holder/auth/callback"

# Oban — manual mode so jobs don't run unless asserted on
config :sovra, Oban, testing: :manual

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
