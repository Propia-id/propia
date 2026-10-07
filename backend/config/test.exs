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
  did_registry: SovraTest.Ethereum.StubDIDRegistry,
  issuer_registry: SovraTest.Ethereum.StubIssuerRegistry,
  revocation_registry: SovraTest.Ethereum.StubRevocationRegistry,
  signature_registry: SovraTest.Ethereum.StubSignatureRegistry,
  ethereum: [
    admin_private_key: "0x" <> String.duplicate("11", 32),
    did_registry_address: "0x0000000000000000000000000000000000000001",
    rpc_url: "http://127.0.0.1:1729"
  ],
  session_secret: "test-secret-must-be-at-least-32-bytes-long-for-hmac!",
  google_client_id: "test-client-id",
  google_client_secret: "test-client-secret",
  google_redirect_uri: "http://localhost:4002/wallet/auth/callback"

# At-rest key for secrets in stored_keys (Sovra.Crypto.StoredKeyCipher).
config :sovra, :stored_keys_encryption_key, String.duplicate("insecure-dev-key", 2)

# aws_credentials starts as an application dependency (pulled in by :aws). Tests
# never touch AWS (the KMS backend is stubbed), so pin it to the env-var
# provider — otherwise it polls the EC2 metadata endpoint on boot.
config :aws_credentials, credential_providers: [:aws_credentials_env]

# ...and it narrates the resulting "no credentials" outcome on every poll. Those
# lines come from its own process, so ExUnit's per-test capture never sees them
# and they land straight in the suite's output. Silenced by application rather
# than by lifting the primary level, which would also hide Sovra.Log events.
config :logger, :aws_credentials_level, :none

# KMS signer — stub the AWS KMS backend (in-memory real P-256 keys) so
# Sovra.Signer.Kms / Router tests exercise the DER/low-s/SPKI paths without AWS.
config :sovra, :kms_backend, SovraTest.Crypto.StubKms

# Sovra.AWS.KMS / ReqHTTPClient tests exercise the real wrapper; this plug
# intercepts its HTTP so nothing reaches AWS.
config :sovra, :aws_req_options, plug: {Req.Test, :aws_kms}

# The relayer key is a fixed secp256k1 stub key (private = 0x11…11) so relayer
# tests are deterministic; StubKms dispatches on the "k1-" prefix.
config :sovra, :signer_service,
  token: "test-signer-token",
  env: "test",
  region: "us-east-1",
  relayer_kms_key_id: "stub-k1-" <> String.duplicate("11", 32)

# Sovra.Crypto.KmsKeyStore reaches the signer over HTTP; a Req.Test plug lets
# those calls be stubbed in the KmsKeyStore test.
config :sovra, :signer,
  url: "http://signer.test",
  token: "test-signer-token",
  req_options: [plug: {Req.Test, :sovra_signer}]

# ---- Metrics -----------------------------------------------------------------
# No metrics in the suite; tests that need the exporter start their own.
config :sovra, Sovra.PromEx, disabled: true
config :sovra, Sovra.Signer.PromEx, disabled: true

# Bind no port.
config :sovra, :metrics_server, enabled: false

# Tests start the monitor explicitly, with a stub reader.
config :sovra, Sovra.Ethereum.Relayer.BalanceMonitor, enabled: false

# Same: the health monitors would otherwise poll the DB, the signer and every
# configured RPC from the application supervisor for the whole suite. Tests that
# want them start them with `enabled: true`.
config :sovra, Sovra.Health, enabled: false
config :sovra, Sovra.Signer.Health, enabled: false

# ...and the readiness RPC probe answers from a map rather than the network,
# for the same reason `relayer_balance_reader` does.
config :sovra, :chain_id_probe, Sovra.Ethereum.ChainIdProbe.Stub

# The stub, not the flag above, is what keeps the suite off the network:
# `runtime.exs` runs after this file and can re-enable the monitor.
config :sovra, :relayer_balance_reader, Sovra.Ethereum.BalanceReader.Stub

# Oban — manual mode so jobs don't run unless asserted on
config :sovra, Oban, testing: :manual

# Mailer — Test adapter so emails are captured for assertions
config :sovra, Sovra.Mailer, adapter: Swoosh.Adapters.Test

# Lower bcrypt cost in tests so the suite stays fast. log_rounds: 4 is a
# small constant; the prod default of 12 is overridden in config.exs.
config :bcrypt_elixir, log_rounds: 4

# Print only warnings and errors during test
# :info, not :warning — Sovra.Log business events are emitted at :info and the
# primary level gates events before any handler sees them, so :warning would
# make every event assertion in test/support/log_helpers.ex unfalsifiable.
# ExUnit.start(capture_log: true) keeps the output quiet: logs are buffered per
# test and printed only for failures.
config :logger, level: :info

# Never report from the suite, even if NEW_RELIC_* is exported in a shell.
config :new_relic_agent, harvest_enabled: false

# :os_mon rides in as an optional dep of the agent and its port programs log on
# VM shutdown. Test-only: the agent does sample memsup/cpu_sup when enabled.
config :os_mon, start_memsup: false, start_cpu_sup: false

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
