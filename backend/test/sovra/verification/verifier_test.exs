defmodule Sovra.Verification.VerifierTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Crypto.P256
  alias Sovra.Issuer
  alias Sovra.Verification

  defmodule StubRegistryOk do
    def is_revoked(_addr, _idx), do: {:ok, false}
    def is_suspended(_addr, _idx), do: {:ok, false}
  end

  defmodule StubRegistryRevoked do
    def is_revoked(_addr, _idx), do: {:ok, true}
    def is_suspended(_addr, _idx), do: {:ok, false}
  end

  defmodule StubRegistrySuspended do
    def is_revoked(_addr, _idx), do: {:ok, false}
    def is_suspended(_addr, _idx), do: {:ok, true}
  end

  # Process-dictionary-backed resolver stub. Each test calls
  # StubResolver.configure(...) before submitting; the verifier reads the
  # configured response. Process-local state avoids cross-test bleed.
  defmodule StubResolver do
    def configure(result), do: Process.put({__MODULE__, :result}, result)
    def resolve(_did), do: Process.get({__MODULE__, :result}, {:error, :not_configured})
  end

  # ── Fixtures ──────────────────────────────────────────────

  defp create_user, do: fixture_user()

  defp create_workspace(name), do: fixture_workspace(name: name).workspace

  defp create_schema(workspace_id) do
    {:ok, schema} =
      Issuer.create_schema(workspace_id, %{
        schema_id: "diploma-#{System.unique_integer([:positive])}",
        credential_type: "UniversityDiploma",
        name: "Diploma",
        claims: [
          %{
            "key" => "studentName",
            "type" => "string",
            "required" => true,
            "disclosable" => true
          },
          %{"key" => "degree", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    schema
  end

  defp build_sd_jwt(issuer_workspace, holder_did, opts) do
    schema = create_schema(issuer_workspace.id)

    {:ok, sd_jwt} =
      Sovra.Issuer.SDJWT.build(
        issuer_workspace,
        schema,
        %{"studentName" => "Alice", "degree" => "BSc"},
        holder_did,
        opts
      )

    sd_jwt
  end

  defp parts_of(sd_jwt_with_disclosures) do
    pieces = String.split(sd_jwt_with_disclosures, "~")

    case Enum.split(pieces, length(pieces) - 1) do
      {[issuer | disclosures], [""]} -> {issuer, disclosures}
      {[issuer | disclosures], [last]} -> {issuer, disclosures ++ [last]}
    end
  end

  defp generate_holder_keys do
    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
    %{priv: priv, x: x, y: y}
  end

  defp build_kb_jwt(holder_keys, payload) do
    header = %{
      "alg" => "ES256",
      "typ" => "kb+jwt",
      "jwk" => %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => Base.url_encode64(holder_keys.x, padding: false),
        "y" => Base.url_encode64(holder_keys.y, padding: false)
      }
    }

    header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
    payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
    signing_input = header_b64 <> "." <> payload_b64
    hash = :crypto.hash(:sha256, signing_input)

    {:ok, %{r: r, s: s}} = P256.sign(hash, holder_keys.priv)
    raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
    sig_b64 = Base.url_encode64(raw_sig, padding: false)

    signing_input <> "." <> sig_b64
  end

  defp build_vp_token(sd_jwt_with_disclosures, kb_jwt) do
    sd_jwt_with_disclosures <> kb_jwt
  end

  defp dcql_query do
    %{
      "credentials" => [
        %{
          "id" => "diploma",
          "format" => "vc+sd-jwt",
          "claims" => [
            %{"path" => ["studentName"]},
            %{"path" => ["degree"]}
          ]
        }
      ]
    }
  end

  defp setup_session(opts \\ []) do
    issuer_ws = create_workspace("Issuer")
    verifier_ws = create_workspace("Verifier")
    holder_keys = generate_holder_keys()
    holder_did = "did:example:" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    sd_jwt =
      build_sd_jwt(
        issuer_ws,
        holder_did,
        Keyword.take(opts, [:status_list_index])
      )

    {:ok, %{session: session}} =
      Verification.create_session(verifier_ws.id, dcql_query())

    {issuer_jwt, disclosures} = parts_of(sd_jwt)
    sd_hash = Sovra.Credentials.SDJWT.compute_sd_hash(issuer_jwt, disclosures)

    %{
      issuer_ws: issuer_ws,
      verifier_ws: verifier_ws,
      holder_keys: holder_keys,
      holder_did: holder_did,
      sd_jwt: sd_jwt,
      issuer_jwt: issuer_jwt,
      disclosures: disclosures,
      session: session,
      sd_hash: sd_hash
    }
  end

  defp default_kb_payload(ctx, overrides \\ %{}) do
    %{
      "iss" => ctx.holder_did,
      "aud" => "verifier:#{ctx.verifier_ws.id}",
      "nonce" => ctx.session.nonce,
      "iat" => System.system_time(:second),
      "sd_hash" => ctx.sd_hash
    }
    |> Map.merge(overrides)
  end

  defp configure_resolver_with_holder_key(ctx) do
    StubResolver.configure(
      {:ok, [%{kty: "EC", crv: "P-256", x: ctx.holder_keys.x, y: ctx.holder_keys.y}]}
    )
  end

  defp submit(ctx, kb_payload, opts) do
    # Default to a resolver that returns the holder's key — most tests want the
    # KB signature path to verify cleanly so they can exercise downstream checks.
    # Tests that want resolver failure or key mismatch override the StubResolver
    # configuration before calling submit.
    if Process.get({StubResolver, :result}) == nil do
      configure_resolver_with_holder_key(ctx)
    end

    opts = Keyword.put_new(opts, :did_resolver, StubResolver)

    kb = build_kb_jwt(ctx.holder_keys, kb_payload)
    vp = build_vp_token(ctx.sd_jwt, kb)
    Verification.submit_presentation(ctx.session.state, vp, opts)
  end

  # ── Tests ────────────────────────────────────────────────

  describe "submit_presentation/3 — happy path" do
    test "marks the session completed and enqueues presentation.verified" do
      ctx = setup_session()

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)

      assert session.status == "completed"
      assert session.holder_did == ctx.holder_did
      assert session.completed_at != nil
      assert session.error == nil

      assert [%{"id" => "diploma", "format" => "vc+sd-jwt", "claims" => claims}] =
               session.presentation_data["credentials"]

      assert claims["studentName"] == "Alice"
      assert claims["degree"] == "BSc"

      assert_enqueued(
        worker: Sovra.Webhooks.DeliveryJob,
        args: %{"event" => "presentation.verified"}
      )
    end
  end

  describe "submit_presentation/3 — failure modes" do
    test "tampered KB-JWT signature -> holder_key_mismatch" do
      ctx = setup_session()
      configure_resolver_with_holder_key(ctx)
      kb = build_kb_jwt(ctx.holder_keys, default_kb_payload(ctx))
      # Replace the signature segment with a syntactically valid but wrong value.
      [h, p, _sig] = String.split(kb, ".")
      bogus_sig = Base.url_encode64(:crypto.strong_rand_bytes(64), padding: false)
      tampered = Enum.join([h, p, bogus_sig], ".")

      assert {:ok, session} =
               Verification.submit_presentation(ctx.session.state, ctx.sd_jwt <> tampered,
                 did_resolver: StubResolver
               )

      assert session.status == "failed"
      assert session.error == "holder_key_mismatch"

      assert_enqueued(
        worker: Sovra.Webhooks.DeliveryJob,
        args: %{"event" => "presentation.failed"}
      )
    end

    test "wrong nonce -> holder_nonce_mismatch" do
      ctx = setup_session()
      payload = default_kb_payload(ctx, %{"nonce" => "not-the-nonce"})
      assert {:ok, session} = submit(ctx, payload, revocation_registry: StubRegistryOk)
      assert session.status == "failed"
      assert session.error == "holder_nonce_mismatch"
    end

    test "wrong audience -> holder_audience_mismatch" do
      ctx = setup_session()

      payload =
        default_kb_payload(ctx, %{"aud" => "verifier:00000000-0000-0000-0000-000000000000"})

      assert {:ok, session} = submit(ctx, payload, revocation_registry: StubRegistryOk)
      assert session.status == "failed"
      assert session.error == "holder_audience_mismatch"
    end

    test "stale iat -> holder_iat_out_of_range" do
      ctx = setup_session()
      payload = default_kb_payload(ctx, %{"iat" => System.system_time(:second) - 3600})
      assert {:ok, session} = submit(ctx, payload, revocation_registry: StubRegistryOk)
      assert session.status == "failed"
      assert session.error == "holder_iat_out_of_range"
    end

    test "sd_hash mismatch -> sd_hash_mismatch" do
      ctx = setup_session()
      payload = default_kb_payload(ctx, %{"sd_hash" => "wrong"})
      assert {:ok, session} = submit(ctx, payload, revocation_registry: StubRegistryOk)
      assert session.status == "failed"
      assert session.error == "sd_hash_mismatch"
    end

    test "DID mismatch (kb iss != sd sub) -> holder_did_mismatch" do
      ctx = setup_session()
      payload = default_kb_payload(ctx, %{"iss" => "did:example:other"})
      assert {:ok, session} = submit(ctx, payload, revocation_registry: StubRegistryOk)
      assert session.status == "failed"
      assert session.error == "holder_did_mismatch"
    end

    test "unknown issuer DID -> unknown_issuer" do
      ctx = setup_session()

      # Tamper the SD-JWT's `iss` to point at a DID we haven't registered.
      [issuer_jwt | rest] = String.split(ctx.sd_jwt, "~")
      [header_b64, payload_b64, sig_b64] = String.split(issuer_jwt, ".")
      {:ok, payload_json} = Base.url_decode64(payload_b64, padding: false)
      {:ok, payload} = Jason.decode(payload_json)
      bogus = Map.put(payload, "iss", "did:sovra:0xdeadbeef")
      bogus_payload_b64 = Base.url_encode64(Jason.encode!(bogus), padding: false)
      tampered_jwt = Enum.join([header_b64, bogus_payload_b64, sig_b64], ".")
      tampered_sd_jwt = Enum.join([tampered_jwt | rest], "~")

      kb = build_kb_jwt(ctx.holder_keys, default_kb_payload(ctx))
      vp = tampered_sd_jwt <> kb

      assert {:ok, session} = Verification.submit_presentation(ctx.session.state, vp)
      assert session.status == "failed"
      assert session.error == "unknown_issuer"
    end

    test "credential revoked -> credential_revoked" do
      ctx = setup_session(status_list_index: 5)

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryRevoked)

      assert session.status == "failed"
      assert session.error == "credential_revoked"
    end

    test "credential suspended -> credential_suspended" do
      ctx = setup_session(status_list_index: 5)

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistrySuspended)

      assert session.status == "failed"
      assert session.error == "credential_suspended"
    end

    test "missing required claim -> missing_required_claim:<path>" do
      issuer_ws = create_workspace("Issuer")
      verifier_ws = create_workspace("Verifier")
      holder_keys = generate_holder_keys()
      holder_did = "did:example:abc"

      schema = create_schema(issuer_ws.id)

      # Build SD-JWT with only `studentName`, omit `degree`.
      {:ok, sd_jwt} =
        Sovra.Issuer.SDJWT.build(
          issuer_ws,
          schema,
          %{"studentName" => "Alice"},
          holder_did
        )

      {:ok, %{session: session}} = Verification.create_session(verifier_ws.id, dcql_query())
      {issuer_jwt, disclosures} = parts_of(sd_jwt)
      sd_hash = Sovra.Credentials.SDJWT.compute_sd_hash(issuer_jwt, disclosures)

      kb_payload = %{
        "iss" => holder_did,
        "aud" => "verifier:#{verifier_ws.id}",
        "nonce" => session.nonce,
        "iat" => System.system_time(:second),
        "sd_hash" => sd_hash
      }

      kb = build_kb_jwt(holder_keys, kb_payload)
      vp = sd_jwt <> kb

      StubResolver.configure(
        {:ok, [%{kty: "EC", crv: "P-256", x: holder_keys.x, y: holder_keys.y}]}
      )

      assert {:ok, s} =
               Verification.submit_presentation(session.state, vp,
                 revocation_registry: StubRegistryOk,
                 did_resolver: StubResolver
               )

      assert s.status == "failed"
      assert s.error == "missing_required_claim:degree"
    end

    test "format mismatch -> format_mismatch" do
      ctx = setup_session()

      query = %{
        "credentials" => [
          %{"id" => "x", "format" => "mso_mdoc", "claims" => [%{"path" => ["a"]}]}
        ]
      }

      {:ok, %{session: session}} = Verification.create_session(ctx.verifier_ws.id, query)
      sd_hash = Sovra.Credentials.SDJWT.compute_sd_hash(ctx.issuer_jwt, ctx.disclosures)

      kb_payload = %{
        "iss" => ctx.holder_did,
        "aud" => "verifier:#{ctx.verifier_ws.id}",
        "nonce" => session.nonce,
        "iat" => System.system_time(:second),
        "sd_hash" => sd_hash
      }

      kb = build_kb_jwt(ctx.holder_keys, kb_payload)
      vp = ctx.sd_jwt <> kb

      configure_resolver_with_holder_key(ctx)

      assert {:ok, s} =
               Verification.submit_presentation(session.state, vp,
                 revocation_registry: StubRegistryOk,
                 did_resolver: StubResolver
               )

      assert s.status == "failed"
      assert String.starts_with?(s.error, "format_mismatch")
    end

    test "resolver returns a different key -> holder_key_mismatch" do
      ctx = setup_session()
      {:ok, %{public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
      StubResolver.configure({:ok, [%{kty: "EC", crv: "P-256", x: x, y: y}]})

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)

      assert session.status == "failed"
      assert session.error == "holder_key_mismatch"
    end

    test "Mallory attack: stolen SD-JWT + attacker-signed KB-JWT -> holder_key_mismatch" do
      # An attacker captures a leaked SD-JWT issued to Alice. She generates
      # her own keypair, builds a fully valid-looking KB-JWT signed with
      # HER key (with HER jwk in the header) but writes Alice's DID in
      # the payload. The on-chain resolver returns Alice's actual passkey,
      # which does not match Mallory's signature → fail-closed.
      ctx = setup_session()
      configure_resolver_with_holder_key(ctx)

      mallory_keys = generate_holder_keys()
      payload = default_kb_payload(ctx)
      mallory_kb = build_kb_jwt(mallory_keys, payload)
      vp = build_vp_token(ctx.sd_jwt, mallory_kb)

      assert {:ok, session} =
               Verification.submit_presentation(ctx.session.state, vp,
                 revocation_registry: StubRegistryOk,
                 did_resolver: StubResolver
               )

      assert session.status == "failed"
      assert session.error == "holder_key_mismatch"
    end

    test "resolver returns empty key list -> holder_did_unresolvable" do
      ctx = setup_session()
      StubResolver.configure({:ok, []})

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)

      assert session.status == "failed"
      assert session.error == "holder_did_unresolvable"
    end

    test "KB-JWT without jwk in header still verifies via resolver" do
      # Locks in the invariant that the verifier never trusts header.jwk.
      # The resolver supplies the authoritative key list; the KB-JWT only
      # needs to provide a signature that verifies under one of those.
      ctx = setup_session()
      configure_resolver_with_holder_key(ctx)

      header = %{"alg" => "ES256", "typ" => "kb+jwt"}
      payload = default_kb_payload(ctx)

      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      signing_input = header_b64 <> "." <> payload_b64
      hash = :crypto.hash(:sha256, signing_input)

      {:ok, %{r: r, s: s}} = P256.sign(hash, ctx.holder_keys.priv)
      raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
      sig_b64 = Base.url_encode64(raw_sig, padding: false)

      kb_no_jwk = signing_input <> "." <> sig_b64
      vp = build_vp_token(ctx.sd_jwt, kb_no_jwk)

      assert {:ok, session} =
               Verification.submit_presentation(ctx.session.state, vp,
                 revocation_registry: StubRegistryOk,
                 did_resolver: StubResolver
               )

      assert session.status == "completed"
    end

    test "resolver returns multiple keys, holder signs with one -> success (rotation grace)" do
      ctx = setup_session()
      {:ok, %{public_key_x: extra_x, public_key_y: extra_y}} = P256.generate_key_pair()

      StubResolver.configure(
        {:ok,
         [
           %{kty: "EC", crv: "P-256", x: extra_x, y: extra_y},
           %{kty: "EC", crv: "P-256", x: ctx.holder_keys.x, y: ctx.holder_keys.y}
         ]}
      )

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)

      assert session.status == "completed"
    end

    test "resolver returns :did_unresolvable -> holder_did_unresolvable" do
      ctx = setup_session()
      StubResolver.configure({:error, :did_unresolvable})

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)

      assert session.status == "failed"
      assert session.error == "holder_did_unresolvable"
    end

    test "resolver returns :did_deactivated -> holder_did_unresolvable" do
      ctx = setup_session()
      StubResolver.configure({:error, :did_deactivated})

      assert {:ok, session} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)

      assert session.status == "failed"
      assert session.error == "holder_did_unresolvable"
    end

    test "session not found -> :session_not_found" do
      assert {:error, :session_not_found} =
               Verification.submit_presentation("no-such-state", "anything")
    end

    test "session already completed -> :session_not_pending" do
      ctx = setup_session()

      assert {:ok, _} = submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)

      assert {:error, :session_not_pending} =
               submit(ctx, default_kb_payload(ctx), revocation_registry: StubRegistryOk)
    end
  end
end
