# Application-level logger overrides (see config/test.exs). :logger has no
# config-file surface for these, so they are applied at boot.
if level = Application.get_env(:logger, :aws_credentials_level) do
  :ok = :logger.set_application_level(:aws_credentials, level)
end

# Logs are captured per test and printed only for failures. SHOW_LOGS=1 turns
# that off, which is how you watch Sovra.Log events go by while debugging.
ExUnit.start(capture_log: System.get_env("SHOW_LOGS") != "1")
Ecto.Adapters.SQL.Sandbox.mode(Sovra.Repo, :manual)
