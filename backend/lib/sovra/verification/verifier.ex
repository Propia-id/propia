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

  use Sovra.Log

  alias Ecto.Multi
  alias Sovra.Credentials.Mdoc
  alias Sovra.Credentials.SDJWT
  alias Sovra.Mdoc.DeviceAuth
  alias Sovra.Mdoc.IssuerTrust
  alias Sovra.Mdoc.MetaNamespace
  alias Sovra.Mdoc.SessionTranscript
  alias Sovra.Repo
  alias Sovra.Verification.RequestObject
  alias Sovra.Verification.Session
  alias Sovra.Webhooks
  alias Sovra.Workspaces

  require Logger

  @kb_iat_max_skew_seconds 300

  @doc """
  Validate a holder-submitted vp_token against a verification session
  identified by its `state` parameter.
  """
  def submit_presentation(session_state, vp_token, opts \\ [])
      when is_binary(session_state) and is_binary(vp_token) do
    case Repo.get_by(Session, state: session_state) do
      nil ->
        # No session to record a failure against, so this is the only trace: a
        # wallet (or a scanner) posted a state we have never issued.
        reject_presentation(nil, nil, :session_not_found)

      %Session{status: "pending"} = session ->
        Log.event(:info, "presentation received",
          event: "presentation.received",
          verification_id: session.id,
          workspace_id: session.workspace_id
        )

        if expired?(session) do
          finalize_failure(fail(session, "session_expired", nil))
        else
          run_pipeline(session, vp_token, opts)
        end

      %Session{} = session ->
        # A completed or failed session being posted to again — a retry, or a
        # replayed vp_token.
        reject_presentation(session.id, session.workspace_id, :session_not_pending)
    end
  end

  defp reject_presentation(verification_id, workspace_id, reason) do
    Log.event(:warning, "presentation rejected before verification",
      event: "presentation.rejected",
      verification_id: verification_id,
      workspace_id: workspace_id,
      reason: reason
    )

    {:error, reason}
  end

  # Both pipelines converge on `complete/3` and `fail/3`, so session
  # finalization, webhooks and the three-outcome contract are shared.
  defp run_pipeline(session, vp_token, opts) do
    case dcql_format(session) do
      "mso_mdoc" ->
        run_mdoc_pipeline(session, vp_token, opts)

      format when format in ["vc+sd-jwt", "dc+sd-jwt"] ->
        run_sd_jwt_pipeline(session, vp_token, opts)

      _ ->
        finalize_failure(fail(session, "invalid_dcql_query", nil))
    end
  end

  defp dcql_format(%Session{dcql_query: %{"credentials" => [%{"format" => format} | _]}}),
    do: format

  defp dcql_format(_session), do: nil

  defp run_sd_jwt_pipeline(session, vp_token, opts) do
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
         :ok <- check_status(sd_jwt_statuses(effective), issuer_ws, session, holder_did, opts),
         {:ok, credentials} <- match_dcql(session.dcql_query, effective, session, holder_did) do
      complete(session, holder_did, credentials)
    else
      {:done, session} -> {:ok, session}
      {:error, _} = err -> err
    end
  end

  # ── mDoc pipeline ──────────────────────────────────────
  #
  # The steps mirror the SD-JWT pipeline's intent, not its mechanics: an mdoc
  # binds its holder by key rather than by DID reference, hashes elements rather
  # than disclosures, and proves freshness through a session transcript rather
  # than through claims in a signed payload.
  defp run_mdoc_pipeline(session, vp_token, opts) do
    with {:ok, encoded} <- unwrap_dcql_response(vp_token, session),
         {:ok, doc} <- parse_device_response(encoded, session),
         {:ok, issuer_ws, issuer_key} <- resolve_mdoc_issuer(doc, session),
         {:ok, mso} <- verify_mdoc_issuer_auth(doc, issuer_key, session),
         :ok <- check_doc_type(doc, mso, session),
         :ok <- check_value_digests(doc, mso, session),
         {:ok, meta} <- extract_meta(doc, session),
         :ok <- check_issuer_address(issuer_ws, meta, session),
         :ok <- check_mandatory_elements(doc, meta, session),
         :ok <- check_mdoc_validity(mso, session, meta.holder_did),
         {:ok, holder_keys} <- resolve_holder_keys(meta.holder_did, session, opts),
         {:ok, device_key} <-
           check_device_key_binding(mso, holder_keys, session, meta.holder_did),
         :ok <- verify_device_auth(doc, session, [device_key], meta.holder_did),
         :ok <- check_status(mdoc_statuses(meta), issuer_ws, session, meta.holder_did, opts),
         {:ok, credentials} <- match_mdoc_dcql(session, doc, meta) do
      complete(session, meta.holder_did, credentials)
    else
      {:done, session} -> {:ok, session}
      {:error, _} = err -> err
    end
  end

  defp parse_device_response(encoded, session) do
    case Mdoc.parse_device_response(encoded) do
      {:ok, doc} -> {:ok, doc}
      {:error, _} -> fail(session, "malformed_vp_token", nil)
    end
  end

  # Two routes, both ending in a key rather than a workspace alone: a generated
  # docType resolves by the address it carries, an ISO one by the `x5chain`
  # leaf. `IssuerTrust` owns the choice, and issuance makes it from the same
  # signal. `check_doc_type/3` closes the loop either way.
  defp resolve_mdoc_issuer(doc, session) do
    case IssuerTrust.resolve(doc.doc_type, doc.issuer_auth) do
      {:ok, workspace, key} -> {:ok, workspace, key}
      {:error, _} -> fail(session, "unknown_issuer", nil)
    end
  end

  # The key comes from resolution rather than from the workspace row, because
  # the two routes sign with different keys — the general signing key, or the
  # document signer the certificate names.
  defp verify_mdoc_issuer_auth(doc, issuer_key, session) do
    case Mdoc.verify_issuer_auth(doc, issuer_key) do
      {:ok, mso} -> {:ok, mso}
      {:error, _} -> fail(session, "credential_signature_invalid", nil)
    end
  end

  # What makes `resolve_mdoc_issuer/2` safe. The document's docType is unsigned,
  # and on the generated route it is what selected the issuer's key; requiring
  # the signed MSO to name the same string means a rewritten docType resolves to
  # a workspace whose key cannot verify this signature.
  #
  # On the certificate route the docType selects nothing — the `x5chain` leaf
  # does — but the check still earns its place: it is what stops a credential
  # issued under one docType from being presented as another, which is the
  # difference between an age attestation and a driving licence.
  defp check_doc_type(doc, mso, session) do
    if Map.get(mso, "docType") == doc.doc_type do
      :ok
    else
      fail(session, "credential_signature_invalid", nil)
    end
  end

  defp check_value_digests(doc, mso, session) do
    case Mdoc.verify_value_digests(doc.items, mso) do
      :ok -> :ok
      {:error, _} -> fail(session, "invalid_disclosure", nil)
    end
  end

  # The meta namespace carries enforcement inputs supplied by the party being
  # enforced against, so an incomplete one is a hard failure rather than absent
  # metadata — which is safe because the whole namespace is issuer-signed.
  defp extract_meta(doc, session) do
    case MetaNamespace.extract(Mdoc.elements(doc.items)) do
      {:ok, meta} -> {:ok, meta}
      {:error, _} -> fail(session, "missing_mandatory_element:#{MetaNamespace.namespace()}", nil)
    end
  end

  # The meta namespace names the issuer's address, and resolution found the
  # workspace independently — by the address inside the docType, or by the key
  # the `x5chain` leaf certifies. Both are issuer-signed, so they cannot
  # disagree unless the credential is malformed, and `Sovra.Mdoc.MetaNamespace`
  # documents that they must agree.
  #
  # Requiring it is what keeps the certificate route from widening who an
  # issuer can claim to be. There the docType names nobody and the chain names
  # only a key, so without this check a workspace holding a document signer
  # could issue credentials carrying another workspace's address — the address
  # the revocation bitmaps and the Issuer Trust Registry are keyed by, and the
  # one `mdoc_statuses/1` is about to be checked against.
  defp check_issuer_address(issuer_ws, meta, session) do
    if issuer_address_matches?(issuer_ws, meta.issuer_address) do
      :ok
    else
      fail(session, "unknown_issuer", meta.holder_did)
    end
  end

  # `MetaNamespace.extract/1` has already required the lowercase form, which is
  # the single form issuance writes.
  defp issuer_address_matches?(%{eoa_address: address}, claimed) when is_binary(address),
    do: String.downcase(address) == claimed

  defp issuer_address_matches?(_workspace, _claimed), do: false

  # Keyed by namespace, because an element identifier is only unique within one
  # — a document with an ISO namespace and a domestic one can hold two
  # `document_number`s, and requiring "the disclosed one" would accept the wrong
  # one.
  defp check_mandatory_elements(doc, meta, session) do
    disclosed =
      MapSet.new(doc.items, &{&1.namespace, &1.element_identifier})

    missing =
      Enum.find_value(meta.mandatory_elements, fn {namespace, elements} ->
        case Enum.find(elements, &(not MapSet.member?(disclosed, {namespace, &1}))) do
          nil -> nil
          element -> {namespace, element}
        end
      end)

    case missing do
      nil ->
        :ok

      {namespace, element} ->
        fail(session, "missing_mandatory_element:#{namespace}.#{element}", meta.holder_did)
    end
  end

  defp check_mdoc_validity(mso, session, holder_did) do
    now = DateTime.utc_now()

    # 18013-5 requires `validUntil` to be later than `validFrom`, and there is
    # deliberately no check for it: the next two clauses already require
    # `validFrom <= now < validUntil`, which implies it. An inverted or empty
    # window is rejected either as not yet valid or as expired, so a third
    # comparison could never fire — `mdoc_verifier_test.exs` pins that.
    with {:ok, validity} <- Mdoc.validity(mso),
         :lt <- DateTime.compare(now, validity.valid_until),
         false <- DateTime.compare(now, validity.valid_from) == :lt,
         # A credential signed in the future is a clock problem or a forgery;
         # either way it is not presentable yet.
         false <- DateTime.diff(validity.signed, now) > @kb_iat_max_skew_seconds do
      :ok
    else
      _ -> fail(session, "credential_expired", holder_did)
    end
  end

  # Where issuance-time binding meets current on-chain authority. Trusting the
  # MSO's deviceKey alone would be ISO-native but would drop the chain binding
  # entirely: the credential would verify while the holder's account contract
  # says nothing about that key, and a rotated-away passkey would work forever.
  # Returns the matched key, because it is the only one `DeviceAuth` may accept
  # a signature from — the rest of the account's keys are current but not bound.
  defp check_device_key_binding(mso, holder_keys, session, holder_did) do
    with {:ok, {x, y}} <- Mdoc.device_key(mso),
         %{} = key <- Enum.find(holder_keys, &(&1.x == x and &1.y == y)) do
      {:ok, key}
    else
      _ -> fail(session, "holder_key_mismatch", holder_did)
    end
  end

  defp verify_device_auth(doc, session, holder_keys, holder_did) do
    transcript = SessionTranscript.build(session)

    case DeviceAuth.verify(
           doc.device_auth,
           transcript,
           doc.doc_type,
           doc.device_name_spaces_bytes,
           holder_keys
         ) do
      :ok ->
        :ok

      {:error, reason} ->
        # The nonce and client_id live inside the transcript, so a stale nonce
        # or a wrong audience surfaces here as a signature failure. Log the
        # inputs: without them this is an opaque crypto error.
        Logger.debug(
          "mdoc device auth failed: #{inspect(reason)} " <>
            "client_id=#{session.client_id} " <>
            "nonce=#{session.nonce} response_uri=#{RequestObject.response_uri(session)}"
        )

        fail(session, device_auth_tag(reason), holder_did)
    end
  end

  defp device_auth_tag(:device_mac_unsupported), do: "device_mac_unsupported"
  defp device_auth_tag(:unsupported_device_auth_alg), do: "unsupported_device_auth_alg"
  defp device_auth_tag(_), do: "holder_key_mismatch"

  # The index is one value; both purposes share it, exactly as the SD-JWT
  # `credentialStatus` array does.
  defp mdoc_statuses(%{status_list_index: index}) do
    [%{purpose: "revocation", index: index}, %{purpose: "suspension", index: index}]
  end

  defp match_mdoc_dcql(session, doc, meta) do
    elements = Mdoc.elements(doc.items)

    match_dcql_entries(session, meta.holder_did, fn entry ->
      match_mdoc_entry(entry, doc.doc_type, elements)
    end)
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

  # `aud` is compared against the `client_id` stored on the session — the exact
  # value that was signed into the authorization request — rather than one
  # recomputed from the workspace, so a later DID change cannot retroactively
  # invalidate (or validate) a presentation already in flight.
  defp check_kb_payload(kb_payload, session, parts, holder_did) do
    expected_aud = session.client_id
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

  # An absent `exp` means "valid indefinitely" (W3C VCDM 2.0 §4.9). Safe to
  # honour here because verify_issuer_signature/2 has already run, so it cannot
  # be stripped by an attacker. Map.fetch/2 keeps that case distinct from an
  # explicit null, which is malformed and must fail.
  #
  # Do not collapse the guard to `exp == nil or exp > now`: Elixir's term
  # ordering makes `"anything" > 1_234_567_890` true.
  defp check_expiry(effective, session, holder_did) do
    now = System.system_time(:second)

    case Map.fetch(effective, "exp") do
      :error -> :ok
      {:ok, exp} when is_integer(exp) and exp > now -> :ok
      {:ok, _} -> fail(session, "credential_expired", holder_did)
    end
  end

  # SD-JWT carries a `credentialStatus` array; an mdoc carries a bare index in
  # the Sovra meta namespace, because the format has no equivalent field. Both
  # normalise to the same list so the chain reads and the failure tags stay in
  # one place.
  defp sd_jwt_statuses(effective) do
    for %{"statusListIndex" => idx_str, "statusPurpose" => purpose} <-
          effective["credentialStatus"] || [],
        {:ok, idx} <- [to_integer(idx_str)],
        do: %{purpose: purpose, index: idx}
  end

  defp check_status(statuses, issuer_workspace, session, holder_did, opts) do
    registry = Keyword.get(opts, :revocation_registry, default_registry())
    issuer_address = issuer_workspace.eoa_address

    Enum.reduce_while(statuses, :ok, fn %{purpose: purpose, index: idx}, _acc ->
      with {:ok, flagged} <- registry_check(registry, purpose, issuer_address, idx) do
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
    match_dcql_entries(session, holder_did, fn entry ->
      match_credential_entry(entry, effective)
    end)
  end

  defp match_dcql(_, _, session, holder_did),
    do: fail(session, "invalid_dcql_query", holder_did)

  # Shared by both pipelines: walk the query's credential entries, collecting
  # matches or failing on the first that cannot be satisfied.
  defp match_dcql_entries(session, holder_did, matcher) do
    case session.dcql_query do
      %{"credentials" => requested} when is_list(requested) ->
        requested
        |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
          case matcher.(entry) do
            {:ok, matched} -> {:cont, {:ok, [matched | acc]}}
            {:error, tag} -> {:halt, fail(session, tag, holder_did)}
          end
        end)
        |> case do
          {:ok, list} -> {:ok, Enum.reverse(list)}
          other -> other
        end

      _ ->
        fail(session, "invalid_dcql_query", holder_did)
    end
  end

  # mdoc claim paths are `[namespace, element_identifier]`, and the returned
  # claims are keyed `"<namespace>.<element_identifier>"` — the same shape the
  # request used, and namespace-qualified because two namespaces may carry an
  # element of the same name. `parse-response.ts`'s `flattenClaims` builds the
  # same keys; a divergence makes an integrator's lookup silently miss.
  defp match_mdoc_entry(%{"format" => "mso_mdoc"} = entry, doc_type, elements) do
    with :ok <- check_doctype_value(entry, doc_type) do
      entry
      |> Map.get("claims", [])
      |> Enum.reduce_while({:ok, %{}}, fn claim, {:ok, acc} ->
        case mdoc_claim_path(claim) do
          {:ok, {namespace, element_id}} ->
            case get_in(elements, [namespace, element_id]) do
              nil ->
                {:halt, {:error, "missing_required_claim:#{namespace}.#{element_id}"}}

              value ->
                {:cont,
                 {:ok, Map.put(acc, "#{namespace}.#{element_id}", Mdoc.to_json_value(value))}}
            end

          :error ->
            {:halt, {:error, "invalid_dcql_query"}}
        end
      end)
      |> case do
        {:ok, claims} -> {:ok, %{"id" => entry["id"], "format" => "mso_mdoc", "claims" => claims}}
        err -> err
      end
    end
  end

  defp match_mdoc_entry(%{"format" => format}, _doc_type, _elements),
    do: {:error, "format_mismatch:#{format}"}

  defp match_mdoc_entry(_, _, _), do: {:error, "format_mismatch"}

  defp check_doctype_value(entry, doc_type) do
    case get_in(entry, ["meta", "doctype_value"]) do
      nil -> :ok
      ^doc_type -> :ok
      _ -> {:error, "doctype_mismatch"}
    end
  end

  # Only the OpenID4VP 1.0 spelling. An earlier draft used an explicit
  # `namespace`/`claim_name` pair; accepting both would leave two ways to say
  # the same thing, and a dashboard emitting the superseded one would keep
  # working until it silently didn't.
  defp mdoc_claim_path(%{"path" => [namespace, element_id]})
       when is_binary(namespace) and is_binary(element_id),
       do: {:ok, {namespace, element_id}}

  defp mdoc_claim_path(_), do: :error

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
      {:ok, %{session: s}} ->
        # Same name as the webhook, and logged after the transaction commits so
        # a rolled-back verification never claims to have succeeded.
        Log.event(:info, "presentation verified",
          event: "presentation.verified",
          verification_id: s.id,
          workspace_id: s.workspace_id,
          holder_did: s.holder_did,
          credential_count: length(credentials)
        )

        {:ok, s}

      {:error, _, reason, _} ->
        {:error, reason}
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
      {:ok, %{session: s}} ->
        {reason, reason_detail} = split_tag(tag)

        # One funnel for every rejection, so the level has to be derived rather
        # than chosen per call site — see level_for/1.
        Log.event(level_for(reason), "presentation failed",
          event: "presentation.failed",
          verification_id: s.id,
          workspace_id: s.workspace_id,
          holder_did: holder_did,
          reason: reason,
          reason_detail: reason_detail
        )

        {:done, s}

      {:error, _, reason, _} ->
        {:error, reason}
    end
  end

  # Two tags embed an unbounded value — a claim path or a requested format —
  # which is useless as an alert facet and unbounded in NRDB cardinality. The
  # stored `session.error` and the webhook payload keep the full tag, because
  # those are a public contract; only the log splits it.
  defp split_tag(tag) do
    case String.split(tag, ":", parts: 2) do
      [reason, detail] -> {reason, detail}
      [reason] -> {reason, nil}
    end
  end

  # Our dependencies failed: DID resolution is down, or the revocation registry
  # could not be read. These are the only tags that mean somebody should look
  # at our infrastructure.
  @our_fault ~w(holder_did_unresolvable status_check_failed)

  # The credential is genuinely unusable and the verifier was told so
  # correctly. Not a problem with anything.
  @credential_state ~w(credential_expired credential_revoked credential_suspended)

  defp level_for(reason) when reason in @our_fault, do: :error
  defp level_for(reason) when reason in @credential_state, do: :info

  # Everything else is the holder's or the verifier's: a malformed token, a
  # nonce mismatch, a claim the credential does not carry. `unknown_issuer` and
  # `credential_signature_invalid` sit here too, deliberately — the common
  # cause of both is a credential we were never meant to accept or one that was
  # tampered with, neither of which is ours to fix. A spike in either is still
  # caught by the faceted alert condition.
  defp level_for(_reason), do: :warning

  defp finalize_failure({:done, session}), do: {:ok, session}
  defp finalize_failure({:error, _} = err), do: err

  defp expired?(%Session{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
end
