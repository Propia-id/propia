defmodule Sovra.Repo.Migrations.AddSignedRequestObjectToVerificationSessions do
  use Ecto.Migration

  # The OID4VP authorization request is now a signed JWT (JAR, RFC 9101) rather
  # than a bare map rebuilt on every read. Signing costs a KMS round-trip, so
  # the request object is minted once at session creation and stored here; the
  # `request_uri` endpoint and the pass-by-value QR both serve that exact JWT.
  #
  # `client_id` is stored beside it because it is a signed, session-scoped
  # commitment: the KB-JWT audience check has to compare against what was
  # actually signed, not against a value recomputed later from workspace state
  # that may have moved on. Sessions already in flight are backfilled with the
  # identifier their QR went out with, so they finish their (10 minute) TTL
  # rather than failing the audience check mid-flow. They have no request
  # object — nothing signed them — which is why only `client_id` is NOT NULL.
  def up do
    alter table(:verification_sessions) do
      add :client_id, :string
      add :request_object, :text
    end

    execute("UPDATE verification_sessions SET client_id = 'verifier:' || workspace_id::text")

    alter table(:verification_sessions) do
      modify :client_id, :string, null: false
    end
  end

  def down do
    alter table(:verification_sessions) do
      remove :client_id
      remove :request_object
    end
  end
end
