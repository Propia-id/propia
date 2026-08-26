defmodule Sovra.MixProject do
  use Mix.Project

  def project do
    [
      app: :sovra,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      releases: releases(),
      listeners: [Phoenix.CodeReloader]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Sovra.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  defp releases do
    [
      sovra: [
        include_executables_for: [:unix]
      ]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:phoenix, "~> 1.8.4"},
      {:phoenix_ecto, "~> 4.5"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, ">= 0.0.0"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:gettext, "~> 1.0"},
      {:jason, "~> 1.2"},
      {:jose, "~> 1.11"},
      {:finch, "~> 0.22"},
      {:req, "~> 0.5"},
      # AWS KMS for the signer service (SERVICE=signer). `aws` = aws-elixir SDK
      # (KMS Sign / GetPublicKey / CreateKey); its HTTP goes through a thin Req
      # adapter (Sovra.AWS.ReqHTTPClient) over our existing Req — no hackney, no
      # separately supervised Finch. `aws_credentials` resolves the EC2 instance
      # role via IMDS on the signer box (env-only elsewhere, see runtime.exs).
      {:aws, "~> 1.0.13"},
      {:aws_credentials, "~> 1.0.5"},
      {:cbor, "~> 1.0"},
      {:ethers, "~> 0.6"},
      {:ethereumex, "~> 0.10"},
      {:ex_keccak, "~> 0.7"},
      {:ex_secp256k1, "~> 0.7"},
      {:bcrypt_elixir, "~> 3.0"},
      {:hammer, "~> 6.2"},
      {:cors_plug, "~> 3.0"},
      {:dns_cluster, "~> 0.2.0"},
      {:bandit, "~> 1.5"},
      {:open_api_spex, "~> 3.21"},
      {:oban, "~> 2.18"},
      {:swoosh, "~> 1.16"},
      # QR codes for the server-rendered document page.
      {:eqrcode, "~> 0.2"},
      {:phoenix_swoosh, "~> 1.2"},

      # Ships logs (and APM data) to New Relic from within the app. Dormant
      # unless NEW_RELIC_APP_NAME + NEW_RELIC_LICENSE_KEY are set (runtime.exs).
      {:new_relic_agent, "~> 1.41"}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "test"]
    ]
  end
end
