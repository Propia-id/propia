defmodule Sovra.Verification.Verifier do
  @moduledoc """
  OID4VP `vp_token` validation pipeline.

  Receives a vp_token submitted via direct_post for a pending verification
  session, runs a fail-fast pipeline (parse → KB-JWT signature → SD-JWT
  issuer signature → DID consistency → disclosure resolution → expiry →
  revocation/suspension status → DCQL minimal match), and finalizes the
  session as `completed` or `failed` while enqueuing the corresponding
  `presentation.verified` / `presentation.failed` webhook.

  Pipeline steps signal three outcomes:
    * `{:ok, value}` — happy path, continue with `value`
    * `{:done, %Session{}}` — recorded failure, session already finalized
    * `{:error, reason}` — system error (DB unavailable, etc.)
  """

  alias Ecto.Multi
  alias Sovra.Credentials.SDJWT
  alias Sovra.Repo
  alias Sovra.Verification.Session
  alias Sovra.Webhooks
  alias Sovra.Workspaces

  @kb_iat_max_skew_seconds 300

  @doc """
  Validate a holder-submitted vp_token against a verification session
  identified by its `state` parameter.
  """
  def submit_presentation(session_state, vp_token, opts \\ [])
      when is_binary(session_state) and is_binary(vp_token) do
    case Repo.get_by(Session, state: session_state) do
      nil ->
        {:error, :session_not_found}

      %Session{status: "pending"} = session ->
        if expired?(session) do
          finalize_failure(fail(session, "session_expired", nil))
        else
          run_pipeline(session, vp_token, opts)
        end

      %Session{} ->
        {:error, :session_not_pending}
    end
  end

  defp run_pipeline(session, vp_token, opts) do
    with {:ok, sd_jwt_vp} <- unwrap_dcql_response(vp_token, session),
         {:ok, parts} <- parse_vp_token(sd_jwt_vp, session),
         {:ok, sd_payload, issuer_ws} <- verify_issuer_signature(parts, session),
         {:ok, holder_did} <- extract_holder_did(sd_payload, session),
         {:ok, holder_keys} <- resolve_holder_keys(holder_did, session, opts),
         {:ok, kb} <- verify_holder_signature(parts, holder_keys, session, holder_did),
         :ok <- check_did_consistency(sd_payload, kb.payload, session, holder_did),
         :ok <- check_kb_payload(kb.payload, session, parts, holder_did),
         {:ok, effective} <-
           resolve_disclosures(sd_payload, parts.disclosures, session, holder_did),
         :ok <- check_expiry(effective, session, holder_did),
         :ok <- check_status(effective, issuer_ws, session, holder_did, opts),
         {:ok, credentials} <- match_dcql(session.dcql_query, effective, session, holder_did) do
      complete(session, holder_did, credentials)
    else
      {:done, session} -> {:ok, session}
      {:error, _} = err -> err
    end
  end

  # ── Pipeline steps ─────────────────────────────────────

  # OID4VP 1.0 §7.2: when the request used DCQL, `vp_token` is a JSON-encoded
  # object whose keys are DCQL credential ids and whose values are the
  # corresponding presentations. Pull the entry that matches the credential
  # the verifier asked for; reject anything that doesn't match that shape.
  defp unwrap_dcql_response(vp_token, session) do
    with {:ok, decoded} <- Jason.decode(vp_token),
         %{"credentials" => [%{"id" => id} | _]} <- session.dcql_query,
         %{^id => sd_jwt_vp} when is_binary(sd_jwt_vp) and sd_jwt_vp != "" <- decoded do
      {:ok, sd_jwt_vp}
    else
      _ -> fail(session, "malformed_vp_token", nil)
    end
  end

  defp parse_vp_token(vp_token, session) do
    case SDJWT.parse(vp_token) do
      {:ok, parts} -> {:ok, parts}
      {:error, _} -> fail(session, "malformed_vp_token", nil)
    end
  end

  defp verify_issuer_signature(parts, session) do
    case SDJWT.decode_jwt(parts.sd_jwt) do
      {:ok, %{payload: %{"iss" => iss} = payload}} ->
        case Workspaces.get_workspace_by_did(extract_issuer_did(iss)) do
          {:ok, workspace} ->
            key = %{x: workspace.signing_public_key_x, y: workspace.signing_public_key_y}

            case SDJWT.verify_issuer_signature(parts.sd_jwt, key) do
              :ok -> {:ok, payload, workspace}
              {:error, _} -> fail(session, "credential_signature_invalid", payload["sub"])
            end

          {:error, _} ->
            fail(session, "unknown_issuer", payload["sub"])
        end

      _ ->
        fail(session, "credential_signature_invalid", nil)
    end
  end

  # Per OID4VCI 1.0, `iss` is the Credential Issuer Identifier — an HTTPS URL
  # whose path component is the workspace DID. Anything else is non-conformant.
  defp extract_issuer_did(iss) when is_binary(iss) do
    case URI.parse(iss) do
      %URI{path: "/" <> did} when did != "" -> did
      _ -> ""
    end
  end

  defp extract_issuer_did(_), do: ""

  defp extract_holder_did(sd_payload, session) do
    case sd_payload["sub"] do
      did when is_binary(did) -> {:ok, did}
      _ -> fail(session, "holder_did_missing", nil)
    end
  end

  defp resolve_holder_keys(holder_did, session, opts) do
    resolver = Keyword.get(opts, :did_resolver, default_resolver())

    case resolver.resolve(holder_did) do
      {:ok, [_ | _] = keys} -> {:ok, keys}
      {:ok, []} -> fail(session, "holder_did_unresolvable", holder_did)
      {:error, _} -> fail(session, "holder_did_unresolvable", holder_did)
    end
  end

  defp verify_holder_signature(parts, holder_keys, session, holder_did) do
    case SDJWT.verify_kb_signature(parts.kb_jwt, holder_keys) do
      {:ok, kb} -> {:ok, kb}
      {:error, _} -> fail(session, "holder_key_mismatch", holder_did)
    end
  end

  defp check_did_consistency(_sd_payload, kb_payload, session, holder_did) do
    case kb_payload["iss"] do
      ^holder_did -> :ok
      _ -> fail(session, "holder_did_mismatch", holder_did)
    end
  end

  defp check_kb_payload(kb_payload, session, parts, holder_did) do
    expected_aud = "verifier:#{session.workspace_id}"
    expected_sd_hash = SDJWT.compute_sd_hash(parts.sd_jwt, parts.disclosures)
    now = System.system_time(:second)
    iat = kb_payload["iat"]

    cond do
      kb_payload["nonce"] != session.nonce ->
        fail(session, "holder_nonce_mismatch", holder_did)

      kb_payload["aud"] != expected_aud ->
        fail(session, "holder_audience_mismatch", holder_did)

      not is_integer(iat) or abs(now - iat) > @kb_iat_max_skew_seconds ->
        fail(session, "holder_iat_out_of_range", holder_did)

      kb_payload["sd_hash"] != expected_sd_hash ->
        fail(session, "sd_hash_mismatch", holder_did)

      true ->
        :ok
    end
  end

  defp resolve_disclosures(sd_payload, disclosures, session, holder_did) do
    case SDJWT.resolve_disclosures(sd_payload, disclosures) do
      {:ok, effective} -> {:ok, effective}
      {:error, _} -> fail(session, "invalid_disclosure", holder_did)
    end
  end

  defp check_expiry(effective, session, holder_did) do
    now = System.system_time(:second)

    case effective["exp"] do
      exp when is_integer(exp) and exp > now -> :ok
      _ -> fail(session, "credential_expired", holder_did)
    end
  end

  defp check_status(effective, issuer_workspace, session, holder_did, opts) do
    registry = Keyword.get(opts, :revocation_registry, default_registry())
    statuses = effective["credentialStatus"] || []
    issuer_address = issuer_workspace.eoa_address

    Enum.reduce_while(statuses, :ok, fn entry, _acc ->
      with %{"statusListIndex" => idx_str, "statusPurpose" => purpose} <- entry,
           {:ok, idx} <- to_integer(idx_str),
           {:ok, flagged} <- registry_check(registry, purpose, issuer_address, idx) do
        cond do
          flagged and purpose == "revocation" ->
            {:halt, fail(session, "credential_revoked", holder_did)}

          flagged and purpose == "suspension" ->
            {:halt, fail(session, "credential_suspended", holder_did)}

          true ->
            {:cont, :ok}
        end
      else
        _ ->
          {:halt, fail(session, "status_check_failed", holder_did)}
      end
    end)
  end

  defp registry_check(registry, "revocation", addr, idx), do: registry.is_revoked(addr, idx)
  defp registry_check(registry, "suspension", addr, idx), do: registry.is_suspended(addr, idx)
  defp registry_check(_registry, _, _, _), do: {:ok, false}

  defp to_integer(s) when is_integer(s), do: {:ok, s}

  defp to_integer(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end

  defp to_integer(_), do: :error

  defp default_registry do
    Application.get_env(:sovra, :revocation_registry, Sovra.Ethereum.RevocationRegistry)
  end

  defp default_resolver do
    Application.get_env(:sovra, :did_resolver, Sovra.DID.Resolver)
  end

  defp match_dcql(%{"credentials" => requested}, effective, session, holder_did)
       when is_list(requested) do
    Enum.reduce_while(requested, {:ok, []}, fn entry, {:ok, acc} ->
      case match_credential_entry(entry, effective) do
        {:ok, matched} -> {:cont, {:ok, [matched | acc]}}
        {:error, tag} -> {:halt, fail(session, tag, holder_did)}
      end
    end)
    |> case do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      other -> other
    end
  end

  defp match_dcql(_, _, session, holder_did),
    do: fail(session, "invalid_dcql_query", holder_did)

  defp match_credential_entry(%{"format" => format} = entry, effective)
       when format in ["dc+sd-jwt", "vc+sd-jwt"] do
    requested_paths = entry["claims"] || []

    claims =
      Enum.reduce_while(requested_paths, {:ok, %{}}, fn %{"path" => path}, {:ok, acc} ->
        case walk_path(effective, path) do
          {:ok, value} when not is_nil(value) ->
            {:cont, {:ok, Map.put(acc, Enum.join(path, "."), value)}}

          _ ->
            {:halt, {:error, "missing_required_claim:#{Enum.join(path, ".")}"}}
        end
      end)

    case claims do
      {:ok, c} -> {:ok, %{"id" => entry["id"], "format" => format, "claims" => c}}
      err -> err
    end
  end

  defp match_credential_entry(%{"format" => format}, _effective) do
    {:error, "format_mismatch:#{format}"}
  end

  defp match_credential_entry(_, _), do: {:error, "format_mismatch"}

  defp walk_path(value, []), do: {:ok, value}

  defp walk_path(map, [key | rest]) when is_map(map) and is_binary(key) do
    case Map.get(map, key) do
      nil -> :error
      v -> walk_path(v, rest)
    end
  end

  defp walk_path(_, _), do: :error

  # ── Session finalizers ─────────────────────────────────

  defp complete(session, holder_did, credentials) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    presentation_data = %{"credentials" => credentials}

    changeset =
      Session.complete_changeset(session, %{
        holder_did: holder_did,
        presentation_data: presentation_data,
        completed_at: now
      })

    Multi.new()
    |> Multi.update(:session, changeset)
    |> Multi.run(:webhook, fn _repo, %{session: s} ->
      Webhooks.enqueue(s.workspace_id, "presentation.verified", %{
        "verification_id" => s.id,
        "holder_did" => s.holder_did,
        "success" => true,
        "credentials" => credentials,
        "completed_at" => DateTime.to_iso8601(s.completed_at)
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{session: s}} -> {:ok, s}
      {:error, _, reason, _} -> {:error, reason}
    end
  end

  # `fail/3` returns either `{:done, session}` (recorded failure — pipeline
  # short-circuits and the caller propagates `{:ok, session}`) or
  # `{:error, reason}` (system error — bubbled up).
  defp fail(session, tag, holder_did) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    changeset =
      Session.fail_changeset(session, %{
        holder_did: holder_did,
        error: tag,
        completed_at: now
      })

    Multi.new()
    |> Multi.update(:session, changeset)
    |> Multi.run(:webhook, fn _repo, %{session: s} ->
      Webhooks.enqueue(s.workspace_id, "presentation.failed", %{
        "verification_id" => s.id,
        "holder_did" => s.holder_did,
        "success" => false,
        "error" => tag,
        "completed_at" => DateTime.to_iso8601(s.completed_at)
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{session: s}} -> {:done, s}
      {:error, _, reason, _} -> {:error, reason}
    end
  end

  defp finalize_failure({:done, session}), do: {:ok, session}
  defp finalize_failure({:error, _} = err), do: err

  defp expired?(%Session{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
end
