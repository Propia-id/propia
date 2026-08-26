import Config

# Env files commonly contain "VAR=" lines, and System.get_env returns "" for
# those — which is truthy, so it would satisfy `|| raise` presence guards and
# bypass `|| default` fallbacks. Treat empty as unset everywhere below.
env = fn name ->
  case System.get_env(name) do
    "" -> nil
    value -> value
  end
end

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/sovra start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :sovra, SovraWeb.Endpoint, server: true
end

config :sovra, SovraWeb.Endpoint, http: [port: String.to_integer(System.get_env("PORT", "4000"))]

# Issuer base URL — set by NixOS module in production, env var in dev
if base_url = System.get_env("ISSUER_BASE_URL") do
  config :sovra, :issuer, base_url: base_url
end

# Issuer frontend URL — drives the CORS allow-list and reset-password links.
# Only :sovra config here: SovraWeb.Plugs.Cors reads it per request, whereas
# `config :cors_plug, origin: ...` would be too late to matter (the endpoint
# initialised CORSPlug at compile time).
if frontend_url = System.get_env("ISSUER_FRONTEND_URL") do
  config :sovra, :issuer_frontend_url, frontend_url
end

# Sender for transactional email. The address must be a verified sender on the
# Postmark account in prod.
if from_address = env.("EMAIL_FROM_ADDRESS") do
  config :sovra, :emails, from: {env.("EMAIL_FROM_NAME") || "Sovra", from_address}
end

# Self-service organization creation. OFF by default (see config.exs). Unset or
# any other value keeps the compile-time default, so a deployment must opt in
# explicitly.
case env.("ORGANIZATION_CREATION_ENABLED") do
  v when v in ~w(true 1) -> config :sovra, :organization_creation_enabled, true
  v when v in ~w(false 0) -> config :sovra, :organization_creation_enabled, false
  _ -> :ok
end

# Self-service registration — the second org-creation path. ON by default
# (config.exs) so dev/test can sign up; REGISTRATION_ENABLED=false closes new
# accounts. Unset or any other value keeps the compile-time default.
case env.("REGISTRATION_ENABLED") do
  v when v in ~w(false 0) -> config :sovra, :registration_enabled, false
  v when v in ~w(true 1) -> config :sovra, :registration_enabled, true
  _ -> :ok
end

# --- New Relic (both roles) ------------------------------------------------
# `:direct` adds a `:logger` primary filter that reports each event and returns
# `:ignore` — which in Erlang's logger means "no opinion", not "drop" — so the
# event still reaches the default handler and normal logging is unaffected.
# Dormant unless both vars are set; app_name is what separates environments.
newrelic_app_name = env.("NEW_RELIC_APP_NAME")
newrelic_license_key = env.("NEW_RELIC_LICENSE_KEY")

if newrelic_app_name && newrelic_license_key do
  config :new_relic_agent,
    app_name: newrelic_app_name,
    license_key: newrelic_license_key,
    # Bound the connect so an outage can't stall the harvester.
    httpc_request_options: [connect_timeout: 5000],
    logs_in_context: :direct
end

# One release, two roles (see Sovra.Application). SERVICE=signer boots the KMS
# signer service (no DB / endpoint); anything else is a full API node.
service = System.get_env("SERVICE", "api")

# KMS signer (API-side): the production key store (Sovra.Crypto.KmsKeyStore)
# signs P-256 workspace keys by calling the dedicated signer service over
# Tailscale. Both must be set; when unset (local dev/test) the software/database
# key stores are used instead and no signer runs.
signer_url = env.("SIGNER_URL")
signer_token = env.("SIGNER_TOKEN")

if signer_url && signer_token do
  config :sovra, :signer, url: signer_url, token: signer_token
end

# KMS signer (service-side): only the SERVICE=signer box talks to AWS KMS. Its
# credentials come from the EC2 instance role via IMDS (default provider chain);
# every other role runs off-AWS (Scaleway) and must never poll the metadata
# endpoint, so it is pinned to the env-var credential provider.
if service == "signer" do
  region = env.("AWS_REGION")

  if config_env() == :prod do
    region || raise "environment variable AWS_REGION is missing (SERVICE=signer)"
    signer_token || raise "environment variable SIGNER_TOKEN is missing (SERVICE=signer)"
  end

  config :sovra, :signer_service,
    port: String.to_integer(env.("SIGNER_PORT") || "4001"),
    env: System.get_env("SOVRA_ENV") || to_string(config_env()),
    region: region,
    token: signer_token,
    # secp256k1 relayer key (on-chain signing). Optional — a signer that only
    # serves P-256 workspace keys leaves it unset.
    relayer_kms_key_id: System.get_env("RELAYER_KMS_KEY_ID")
else
  config :aws_credentials, credential_providers: [:aws_credentials_env]
end

# Fail fast: an API node whose key store is KmsKeyStore (the prod default) is
# useless without a reachable signer, so require both at boot rather than
# discovering it on the first signature.
if config_env() == :prod and service != "signer" and
     Application.get_env(:sovra, :key_store) == Sovra.Crypto.KmsKeyStore do
  signer_url || raise "environment variable SIGNER_URL is missing (required by KmsKeyStore)"
  signer_token || raise "environment variable SIGNER_TOKEN is missing (required by KmsKeyStore)"
end

# Ethereum / on-chain relayer. Two signing backends:
#   * :local — signs with ADMIN_PRIVATE_KEY in-process (dev/test/local).
#   * :kms   — signs via the signer service's secp256k1 relayer key; no key
#              material on the API node (production).
# Local wins when ADMIN_PRIVATE_KEY is set; otherwise KMS is used once a signer
# and a DID registry are configured. On-chain stays disabled if neither.
# Block explorer used for the transaction link on rendered documents. Display
# only: nothing depends on it being reachable.
config :sovra, :explorer_url, System.get_env("EXPLORER_URL", "https://explorer.testnet.sovra.io")

admin_pk = System.get_env("ADMIN_PRIVATE_KEY")

cond do
  admin_pk not in [nil, ""] ->
    config :sovra, :ethereum,
      relayer_backend: :local,
      rpc_url: System.get_env("L2_RPC_URL", "http://127.0.0.1:1729"),
      chain_id: String.to_integer(env.("CHAIN_ID") || "65536999"),
      admin_private_key: admin_pk,
      did_registry_address: System.fetch_env!("DID_REGISTRY_ADDRESS"),
      issuer_registry_address: System.fetch_env!("ISSUER_REGISTRY_ADDRESS"),
      revocation_registry_address: System.get_env("REVOCATION_REGISTRY_ADDRESS"),
      signature_registry_address: System.get_env("SIGNATURE_REGISTRY_ADDRESS")

  signer_url not in [nil, ""] and System.get_env("DID_REGISTRY_ADDRESS") not in [nil, ""] ->
    config :sovra, :ethereum,
      relayer_backend: :kms,
      rpc_url: System.get_env("L2_RPC_URL", "http://127.0.0.1:1729"),
      chain_id: String.to_integer(env.("CHAIN_ID") || "65536999"),
      did_registry_address: System.fetch_env!("DID_REGISTRY_ADDRESS"),
      issuer_registry_address: System.fetch_env!("ISSUER_REGISTRY_ADDRESS"),
      revocation_registry_address: System.get_env("REVOCATION_REGISTRY_ADDRESS"),
      signature_registry_address: System.get_env("SIGNATURE_REGISTRY_ADDRESS")

  true ->
    :ok
end

# Holder identity source for DID resolution. "aligned" reads the holder's
# WebAuthn key from the AlignedAccount contract (point L2_RPC_URL/CHAIN_ID at
# the chain where it's deployed, e.g. Base Sepolia); anything else uses the
# legacy SovraWalletV1 passkey. Defaults to legacy so existing holders keep
# verifying until the cutover is deliberately enabled.
config :sovra, :did,
  identity_source:
    if(System.get_env("SOVRA_IDENTITY_SOURCE") == "aligned", do: :aligned, else: :legacy)

# API-node-only prod config. The SERVICE=signer role has no Repo, endpoint, or
# Guardian/Google auth (see Sovra.Application), so it must boot without these
# env vars; its own requirements are enforced in the signer branch above.
if config_env() == :prod and service != "signer" do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :sovra, Sovra.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # For machines with several cores, consider starting multiple pools of `pool_size`
    # pool_count: 4,
    socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  # At-rest encryption key for secrets in the stored_keys table (webhook HMAC
  # secrets — see Sovra.Crypto.StoredKeyCipher).
  stored_keys_encryption_key =
    env.("STORED_KEYS_ENCRYPTION_KEY") ||
      raise """
      environment variable STORED_KEYS_ENCRYPTION_KEY is missing.
      You can generate one by calling: openssl rand -base64 32
      """

  stored_keys_encryption_key =
    case Base.decode64(stored_keys_encryption_key) do
      {:ok, key} when byte_size(key) == 32 ->
        key

      _ ->
        raise "STORED_KEYS_ENCRYPTION_KEY must be the base64 encoding of exactly 32 bytes"
    end

  config :sovra, :stored_keys_encryption_key, stored_keys_encryption_key

  host = System.get_env("PHX_HOST") || "example.com"

  config :sovra, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  # Google OAuth (holder auth) — used only by the legacy identity source's
  # login flow. In aligned mode (SOVRA_IDENTITY_SOURCE=aligned) holder identity
  # comes from the AlignedAccount contract, so the Google credentials may be
  # unset; GoogleAuthProvider reads them lazily per request.
  google_env = fn name ->
    env.(name) ||
      if System.get_env("SOVRA_IDENTITY_SOURCE") == "aligned" do
        nil
      else
        raise "environment variable #{name} is missing (required unless SOVRA_IDENTITY_SOURCE=aligned)"
      end
  end

  config :sovra,
    session_secret: System.fetch_env!("GUARDIAN_SESSION_SECRET"),
    google_client_id: google_env.("GOOGLE_CLIENT_ID"),
    google_client_secret: google_env.("GOOGLE_CLIENT_SECRET"),
    google_redirect_uri: google_env.("GOOGLE_REDIRECT_URI")

  config :sovra, SovraWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  # Transactional email. Both are checked at boot: a deployment that can't send
  # invitations or password resets should fail here, not on the first delivery.
  config :sovra, Sovra.Mailer,
    adapter: Swoosh.Adapters.Postmark,
    api_key: env.("POSTMARK_API_KEY") || raise("environment variable POSTMARK_API_KEY is missing")

  config :swoosh, api_client: Swoosh.ApiClient.Req

  env.("EMAIL_FROM_ADDRESS") ||
    raise """
    environment variable EMAIL_FROM_ADDRESS is missing.
    Set it to a sender address verified on the Postmark account.
    """

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :sovra, SovraWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :sovra, SovraWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
end
