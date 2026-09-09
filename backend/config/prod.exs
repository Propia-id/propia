import Config

# Force using SSL in production. This also sets the "strict-security-transport"
# header, known as HSTS. Note `:force_ssl` is required to be set at compile-time.
#
# `:exclude` must be nested INSIDE the force_ssl options — Plug.SSL only reads
# what is passed to it. As a sibling key it is an inert Endpoint setting, which
# is why the probe paths got a 301 at the edge: cloudflared forwards the
# original Host, so `conn.host` is the public FQDN and the hosts entry never
# applies.
config :sovra, SovraWeb.Endpoint,
  force_ssl: [
    rewrite_on: [:x_forwarded_proto],
    exclude: [
      hosts: ["localhost", "127.0.0.1"],
      paths: ["/health", "/ready"]
    ]
  ]

# Do not print debug messages in production
config :logger, level: :info

# Runtime production configuration, including reading
# of environment variables, is done on config/runtime.exs.
