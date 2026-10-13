defmodule Sovra.Log do
  @moduledoc """
  Canonical business-event logging.

  Every business event goes through `event/3`, which emits a `Logger` call
  carrying a registered `:event` name plus flat, scalar metadata. Three
  properties of the New Relic pipeline dictate that shape:

    * Only `Logger` calls whose message is chardata reach NRDB as `Log`
      records. Erlang `{format, args}` logs and OTP/SASL reports are
      journald-only, so a report-style call would produce an alert condition
      that applies and never fires. `event/3` therefore takes a binary
      message.

    * `NewRelic.LogsInContext` forwards `Logger` metadata as
      `metadata.<key>` attributes, deep-flattening maps and structs on the way.
      A map in metadata is a data leak rather than a formatting choice: passing
      a credential offer would publish its claim values to NRDB as queryable
      attributes. `event/3` rejects non-scalars in dev and test, and drops them
      in production.

    * **At most 10 of those attributes survive**, and the rest are discarded
      silently. `NewRelic.Util.deep_flatten/1` slices any map to its first 10
      entries — a fair guard against one careless struct becoming hundreds of
      attributes — but `custom_metadata/1` wraps the *whole* metadata map in one
      nesting level first, so the guard lands on everything you log. It then
      deletes the `metadata.size` marker that recorded the true count, which is
      why truncation leaves no trace. Which 10 survive is map iteration order,
      not a priority anyone chose.

      The budget therefore includes the ambient context `put_context/1` has
      already set. `test/sovra/log_budget_test.exs` fails when a call site
      exceeds it. Verified against new_relic_agent 1.41.0, unchanged on
      upstream master, no open issue.

    * The agent derives `module.name`, `function.name` and `line.number` from
      the caller's `Logger` metadata. `event/3` is therefore a **macro**, so
      it expands at the call site and reports the real source location rather
      than this module. Callers need `require Sovra.Log`, the same way they
      already need `require Logger`.

  Event names live in `@events` and are frozen by `test/sovra/log_test.exs`.
  Alert conditions in `infra/terraform/modules/newrelic_alerts/main.tf` match
  on `metadata.event`, so renaming one silently disarms an alert — the freeze
  test is what turns that into a CI failure instead of a production surprise.

  ## Usage

      use Sovra.Log

      Log.event(:info, "credential issued",
        event: "credential.issued",
        credential_id: cred.id,
        workspace_id: cred.issuer_id
      )

  `use Sovra.Log` rather than a bare `alias`, because `event/3` is a macro:
  with an alias and no `require`, `Log.event(...)` compiles into a call to a
  *function* that does not exist and raises `UndefinedFunctionError` at
  runtime, in the logging call itself — precisely the failure this module
  exists to avoid. `__using__/1` makes that impossible to get wrong.

  There is deliberately one entry point and no per-level shorthand, so
  `grep -rn "Log.event"` finds every business event in the backend.
  """

  @doc """
  Requires and aliases this module, so `Log.event/3` resolves as the macro it
  is. See the note in the moduledoc on why this is not just an alias.
  """
  defmacro __using__(_opts) do
    quote do
      require Sovra.Log

      alias Sovra.Log
    end
  end

  # ── Event catalogue ────────────────────────────────────
  #
  # Every name `event/3` will accept. Frozen by test/sovra/log_test.exs and
  # read by NRQL alert conditions; grows one phase at a time, in the same
  # commit as the code that emits the new names and the Terraform condition
  # that watches them. See docs/plans/backend-logging.md.
  @events ~w(
    admin.issuer_account.created

    app.boot

    auth.api_key.rejected
    auth.logged_out
    auth.login.failed
    auth.login.succeeded
    auth.origin.rejected
    auth.password_reset.completed
    auth.password_reset.rejected
    auth.password_reset.requested
    auth.rate_limit.denied
    auth.refresh_token.reuse_detected
    auth.registered
    auth.registration.rejected
    auth.session.refresh_rejected
    auth.session.refreshed
    auth.session.rejected

    authz.denied

    credential.issuance.errored

    credential.design.deleted
    credential.design.updated
    credential.issued
    credential.offer.code_regenerated
    credential.offer.created
    credential.request.rejected
    credential.revoked
    credential.schema.chain_registered
    credential.schema.chain_registration_failed
    credential.schema.created
    credential.schema.deleted
    credential.schema.rejected
    credential.schema.revised
    credential.status_change.failed
    credential.status_change.rejected
    credential.status_change.requested
    credential.suspended
    credential.token.exchanged
    credential.unsuspended

    chain.tx.confirmed
    chain.tx.receipt_timeout
    chain.tx.receipt_unexpected
    chain.tx.reverted
    chain.tx.send_failed
    chain.tx.submitted

    did.resolution.failed

    document.anchored
    document.anchoring_failed
    document.rejected
    document.signed
    document.visibility.changed

    email.enqueue_failed
    email.failed
    email.sent

    guardian.auth.rejected
    guardian.authenticated
    guardian.oauth.authenticated
    guardian.oauth.rejected
    guardian.oauth_binding.mismatch
    guardian.onboard.rejected
    guardian.onboarded
    guardian.recovery.errored
    guardian.recovery.finalized
    guardian.recovery.initiated
    guardian.recovery.rejected
    guardian.recovery_key.rotation_confirmed
    guardian.recovery_key.rotation_failed
    guardian.recovery_key.rotation_started

    health.check.failed
    http.request

    invitation.accepted
    invitation.code_requested
    invitation.created
    invitation.rejected
    invitation.revoked

    issuance.status_index.exhausted
    issuance.status_index.widened
    issuance.tx_code.locked_out

    presentation.failed
    presentation.received
    presentation.rejected
    presentation.request.created
    presentation.request.expired
    presentation.request.fetched
    presentation.request.rejected
    presentation.verified

    org.created
    org.deactivated
    org.member.added

    signer.misconfigured
    signer.request.failed
    signer.response.errored
    signer.unreachable

    webhook.delivered
    webhook.discarded
    webhook.enqueue_failed
    webhook.enqueued
    webhook.failed
    webhook.skipped

    workspace.api_key.created
    workspace.api_key.revoked
    workspace.created
    workspace.member.added
    workspace.member.change_rejected
    workspace.member.removed
    workspace.member.role_changed
    workspace.provisioning.completed
    workspace.provisioning.step_completed
    workspace.provisioning.step_failed
    workspace.webhook.created
    workspace.webhook.deleted
    workspace.webhook.secret_rotated
    workspace.webhook.updated
  )

  @events_set MapSet.new(@events)

  @scalar_structs [Date, DateTime, NaiveDateTime, Time]

  @doc "Every registered event name, sorted. The freeze test asserts on this."
  def events, do: Enum.sort(@events)

  @doc """
  Emits a business event.

  `level` is `:info` for an expected business event, `:warning` for a
  client-caused or otherwise expected failure, and `:error` for a failure on
  our side that a human may need to act on.

  `metadata` must include an `:event` key naming a registered event, and every
  value must be a scalar (binary, number, boolean, atom, or a `Date`/`Time`
  struct). Anything else raises in dev and test; in production the value is
  replaced and the event still ships, because a logging call must never be the
  thing that fails a request.
  """
  defmacro event(level, message, metadata) do
    quote do
      require Logger

      Logger.log(
        unquote(level),
        unquote(message),
        Sovra.Log.prepare(unquote(metadata))
      )
    end
  end

  # Keys whose value is personal data. A call site passes the raw value under
  # one of these names and never decides the policy itself:
  #
  #   * with LOG_FINGERPRINT_KEY set  -> `<key>_fp`, the keyed digest
  #   * without it                    -> `<key>`, the raw value
  #
  # The attribute NAME is what differs, deliberately. Putting both under
  # `email_fp` would mean a support query silently returning a mix of digests
  # and addresses under a name claiming they are digests — worse than either
  # choice on its own. It also gives operators the detector for a production
  # node running with no key:
  #
  #     SELECT count(*) FROM Log WHERE `metadata.email` IS NOT NULL
  @sensitive_keys [:email, :ip, :oauth_subject, :expected_oauth_subject, :presented_oauth_subject]

  @doc """
  Validates and sanitizes event metadata. Called by the `event/3` expansion and
  by `put_context/1` — not meant to be used directly.
  """
  def prepare(metadata) when is_list(metadata) do
    metadata
    |> validate_event_name()
    |> Enum.flat_map(&resolve_sensitive/1)
    |> Enum.flat_map(&sanitize/1)
  end

  # An email also contributes its domain, always in the clear: useful on its own
  # — one tenant's whole organization failing to authenticate — and no
  # individual risk.
  defp resolve_sensitive({:email, value}) when is_binary(value) do
    protect(:email, value) ++ [{:email_domain, email_domain(value)}]
  end

  defp resolve_sensitive({key, value}) when key in @sensitive_keys and is_binary(value) do
    protect(key, value)
  end

  defp resolve_sensitive({key, _value}) when key in @sensitive_keys, do: []
  defp resolve_sensitive(pair), do: [pair]

  defp protect(key, value) do
    case fingerprint(value) do
      nil -> [{key, normalize(value)}]
      fp -> [{:"#{key}_fp", fp}]
    end
  end

  # ── Request and job context ────────────────────────────

  @doc """
  Merges caller-identifying metadata into the process's `Logger` metadata, so
  every later line in the same request carries it without call-site effort.

  Set from the authentication plugs. `nil` and empty values are dropped rather
  than recorded — New Relic omits empty attributes anyway, and a `nil` in the
  console formatter is noise.
  """
  def put_context(metadata) when is_list(metadata) do
    metadata
    |> Enum.flat_map(&resolve_sensitive/1)
    |> Enum.flat_map(&sanitize/1)
    |> Logger.metadata()
  end

  @doc """
  Adds the current `request_id` to Oban job args so the job's own log lines can
  be joined to the request that enqueued it.

  New Relic's `trace.id` does not cross the job boundary — an Oban job is a
  separate transaction with its own trace — so this is the only id that spans
  the two. A no-op when there is no request in scope (a cron job, a release
  task, a test).
  """
  def job_args(args) when is_map(args) do
    case Logger.metadata()[:request_id] do
      nil -> args
      request_id -> Map.put(args, :request_id, request_id)
    end
  end

  @doc """
  Restores job context onto the worker process's `Logger` metadata. Call it
  first thing in `perform/1`.

  Oban runs each attempt in a fresh task, so metadata never carries over on its
  own; `oban_job_id` ties the attempts of one job together.
  """
  def adopt_job_context(%Oban.Job{id: id, args: args, attempt: attempt}) do
    put_context(
      request_id: args["request_id"],
      oban_job_id: id,
      oban_attempt: attempt
    )
  end

  @doc """
  Reduces an error term to something loggable.

  Contexts return `{:error, term}` where the term may be an atom, an
  `Ecto.Changeset`, an exception, or a tagged tuple wrapping any of those. A
  changeset must never be logged as-is: its `changes` hold exactly what the
  user submitted — an email address, a full name, a credential's claims — and
  New Relic would flatten them into queryable attributes. This keeps the
  *shape* of the failure and drops the values, reducing a changeset to its
  invalid field names.

  Best-effort by design: a call site that knows its own failure modes should
  pass an atom and skip this.
  """
  def reason(value) when is_atom(value) or is_binary(value), do: value

  def reason(%Ecto.Changeset{errors: errors}) do
    "invalid:" <> Enum.map_join(errors, ",", fn {field, _} -> to_string(field) end)
  end

  def reason({tag, inner}) when is_atom(tag), do: "#{tag}:#{reason(inner)}"

  def reason(value) when is_exception(value),
    do: value |> Exception.message() |> String.slice(0, 200)

  # A struct we do not recognize: name the type, never its contents.
  def reason(%module{}), do: inspect(module)

  def reason(value) when is_map(value), do: "map"
  def reason(value), do: inspect(value, limit: 3, printable_limit: 64)

  # ── Fingerprints ───────────────────────────────────────

  @doc """
  The keyed fingerprint of `value`, or `nil` when `LOG_FINGERPRINT_KEY` is
  unset.

  Call sites do not normally use this: pass the raw value under a sensitive key
  (see `@sensitive_keys`) and `prepare/1` applies the policy. This is the raw
  computation, for `mix sovra.fingerprint` and for tests.
  """
  def fingerprint(value) when is_binary(value) do
    case fingerprint_key() do
      nil ->
        nil

      key ->
        :hmac
        |> :crypto.mac(:sha256, key, normalize(value))
        |> Base.encode16(case: :lower)
        |> binary_part(0, 12)
    end
  end

  def fingerprint(_), do: nil

  @doc """
  The domain part of an email address, or `nil`.

  Safe to log as-is and useful on its own: one tenant's whole organization
  failing to authenticate is visible in the domain alone.
  """
  def email_domain(email) when is_binary(email) do
    case email |> normalize() |> String.split("@") do
      [_, domain] when domain != "" -> domain
      _ -> nil
    end
  end

  def email_domain(_), do: nil

  defp normalize(value), do: value |> String.trim() |> String.downcase()

  defp fingerprint_key do
    case Application.get_env(:sovra, :log_fingerprint_key) do
      key when is_binary(key) and byte_size(key) > 0 -> key
      _ -> nil
    end
  end

  # ── Validation ─────────────────────────────────────────

  defp validate_event_name(metadata) do
    name = Keyword.get(metadata, :event)

    cond do
      is_binary(name) and MapSet.member?(@events_set, name) ->
        metadata

      strict?() ->
        raise ArgumentError, """
        unregistered log event: #{inspect(name)}

        Add it to @events in lib/sovra/log.ex, update the frozen list in
        test/sovra/log_test.exs, and — if it is worth alerting on — add the
        condition to infra/terraform/modules/newrelic_alerts/main.tf in the
        same commit.
        """

      true ->
        metadata
    end
  end

  # New Relic deep-flattens maps and structs into attributes, so a non-scalar
  # value is a disclosure risk, not a cosmetic problem. Fail loudly where a
  # test will catch it; degrade quietly in production.
  defp sanitize({_key, nil}), do: []
  defp sanitize({_key, ""}), do: []

  defp sanitize({key, value}) when is_number(value) or is_boolean(value) or is_atom(value),
    do: [{key, value}]

  defp sanitize({key, %struct{} = value}) when struct in @scalar_structs, do: [{key, value}]

  defp sanitize({key, value}) when is_binary(value) do
    if String.valid?(value) do
      [{key, value}]
    else
      # Raw bytes in a log line are usually key material that arrived by way of
      # a struct field. Never let them reach the wire.
      unsafe(key, value, "a non-UTF-8 binary")
    end
  end

  defp sanitize({key, value}), do: unsafe(key, value, "a #{type_name(value)}")

  defp unsafe(key, value, description) do
    if strict?() do
      raise ArgumentError, """
      log metadata #{inspect(key)} is #{description}, which is not loggable.

      New Relic forwards metadata as queryable attributes and deep-flattens
      maps and structs, so this would publish #{inspect(value, limit: 3)} to
      NRDB. Pass ids, counts, field names or a hash prefix instead — never a
      map, a changeset, params, or a credential's claims.
      """
    else
      [{key, "[unloggable]"}]
    end
  end

  defp type_name(value) when is_map(value), do: "map"
  defp type_name(value) when is_list(value), do: "list"
  defp type_name(value) when is_tuple(value), do: "tuple"
  defp type_name(value) when is_function(value), do: "function"
  defp type_name(value) when is_pid(value), do: "pid"
  defp type_name(_), do: "unsupported value"

  defp strict?, do: Application.get_env(:sovra, :env) in [:dev, :test]
end
