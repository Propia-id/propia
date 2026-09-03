defmodule Mix.Tasks.Sovra.Fingerprint do
  @moduledoc """
  Computes the log fingerprint for an email address or OAuth subject.

  ## Usage

      mix sovra.fingerprint someone@example.gov

  Logs never carry email addresses — they leave the host for New Relic — so
  auth events are tagged with `email_fp` instead. This turns the address on a
  support ticket into the value to query:

      SELECT * FROM Log WHERE `metadata.email_fp` = '<output>' SINCE 7 days ago

  Requires `LOG_FINGERPRINT_KEY`, and must run on a host configured with the
  same key as the environment whose logs are being searched — a different key
  gives a different, silently useless fingerprint.

  If the target environment has no key set, its logs carry the raw address
  under `metadata.email` instead and no fingerprint is needed:

      SELECT * FROM Log WHERE `metadata.email` = 'someone@example.gov'
  """

  use Mix.Task

  @shortdoc "Compute the log fingerprint for an email or OAuth subject"

  @impl Mix.Task
  def run([value]) do
    Mix.Task.run("app.start")

    case Sovra.Log.fingerprint(value) do
      nil ->
        Mix.shell().error("""
        LOG_FINGERPRINT_KEY is not set, so no fingerprint can be computed.

        With no key, logs carry the raw address under `metadata.email` and you
        can query it directly:

            SELECT * FROM Log WHERE `metadata.email` = '#{value}'

        To fingerprint instead, set the key to the same value as the
        environment whose logs you are searching (see
        infra/ansible/playbooks/api/templates/sovra.env.j2).
        """)

        exit({:shutdown, 1})

      fingerprint ->
        Mix.shell().info(fingerprint)
    end
  end

  def run(_) do
    Mix.shell().error("Usage: mix sovra.fingerprint EMAIL_OR_SUBJECT")
    exit({:shutdown, 1})
  end
end
