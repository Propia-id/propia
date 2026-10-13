defmodule SovraWeb.Verify.DirectPostControllerTest do
  use SovraWeb.ConnCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Crypto.P256
  alias Sovra.Issuer
  alias Sovra.Verification

  setup do
    # Stub the on-chain registry so check_status returns clean for any
    # credentialStatus the SD-JWT might carry. Also install a stub DID
    # resolver — the controller calls submit_presentation/2 without opts,
    # so dependency injection has to go through Application config.
    prev_reg = Application.get_env(:sovra, :revocation_registry)
    prev_res = Application.get_env(:sovra, :did_resolver)
    Application.put_env(:sovra, :revocation_registry, __MODULE__.StubRegistry)
    Application.put_env(:sovra, :did_resolver, __MODULE__.StubResolver)

    on_exit(fn ->
      restore(:revocation_registry, prev_reg)
      restore(:did_resolver, prev_res)
      Application.delete_env(:sovra, {__MODULE__.StubResolver, :keys})
    end)

    :ok
  end

  defp restore(key, nil), do: Application.delete_env(:sovra, key)
  defp restore(key, val), do: Application.put_env(:sovra, key, val)

  defmodule StubRegistry do
    def is_revoked(_, _), do: {:ok, false}
    def is_suspended(_, _), do: {:ok, false}
    # Workspace provisioning initializes the bitmaps.
    def initialize_bitmap(_, _), do: {:ok, "0xstubtxhash"}
  end

  defmodule StubResolver do
    def resolve(_did) do
      case Application.get_env(:sovra, {__MODULE__, :keys}) do
        keys when is_list(keys) and keys != [] -> {:ok, keys}
        _ -> {:error, :did_unresolvable}
      end
    end
  end

  defp create_workspace(name) do
    workspace = provision_workspace(fixture_workspace(name: name).workspace)
    fixture_webhook(workspace)
    workspace
  end

  defp create_schema(workspace_id) do
    {:ok, schema} =
      Issuer.create_schema(workspace_id, %{
        schema_id: "diploma-#{System.unique_integer([:positive])}",
        credential_type: "UniversityDiploma",
        name: "Diploma",
        claims: [
          %{"key" => "studentName", "type" => "string", "required" => true, "disclosable" => true}
        ],
        validity_period: "1y"
      })

    schema
  end

  defp build_kb(holder_keys, payload) do
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

    h = Base.url_encode64(Jason.encode!(header), padding: false)
    p = Base.url_encode64(Jason.encode!(payload), padding: false)
    input = h <> "." <> p
    hash = :crypto.hash(:sha256, input)
    {:ok, %{r: r, s: s}} = P256.sign(hash, holder_keys.priv)
    sig = Base.url_encode64(P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32), padding: false)
    input <> "." <> sig
  end

  defp setup_pending_session(requested_paths \\ [["studentName"]]) do
    issuer_ws = create_workspace("Issuer")
    verifier_ws = create_workspace("Verifier")
    schema = create_schema(issuer_ws.id)
    holder_did = "did:example:" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
    holder_keys = %{priv: priv, x: x, y: y}

    {:ok, sd_jwt} =
      Sovra.Issuer.SDJWT.build(issuer_ws, schema, %{"studentName" => "Alice"}, holder_did)

    dcql = %{
      "credentials" => [
        %{
          "id" => "diploma",
          "format" => "vc+sd-jwt",
          "claims" => Enum.map(requested_paths, &%{"path" => &1})
        }
      ]
    }

    {:ok, %{session: session}} = Verification.create_session(verifier_ws.id, dcql)
    pieces = String.split(sd_jwt, "~")

    {issuer_jwt, disclosures} =
      case Enum.split(pieces, length(pieces) - 1) do
        {[i | d], [""]} -> {i, d}
        {[i | d], [last]} -> {i, d ++ [last]}
      end

    sd_hash = Sovra.Credentials.SDJWT.compute_sd_hash(issuer_jwt, disclosures)

    %{
      sd_jwt: sd_jwt,
      verifier_ws: verifier_ws,
      session: session,
      holder_keys: holder_keys,
      holder_did: holder_did,
      sd_hash: sd_hash
    }
  end

  defp valid_vp_token(ctx) do
    Jason.encode!(%{"diploma" => ctx.sd_jwt <> build_kb(ctx.holder_keys, kb_payload(ctx))})
  end

  # OID4VP 1.0 §8.2: the wallet form-encodes the Authorization Response.
  defp direct_post(conn, session_id, params) do
    conn
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
    |> post("/wallet/verifier/direct_post/#{session_id}", URI.encode_query(params))
  end

  defp trust_holder_keys(ctx) do
    Application.put_env(:sovra, {StubResolver, :keys}, [
      %{kty: "EC", crv: "P-256", x: ctx.holder_keys.x, y: ctx.holder_keys.y}
    ])
  end

  defp kb_payload(ctx) do
    %{
      "iss" => ctx.holder_did,
      "aud" => ctx.session.client_id,
      "nonce" => ctx.session.nonce,
      "iat" => System.system_time(:second),
      "sd_hash" => ctx.sd_hash
    }
  end

  describe "POST /wallet/verifier/direct_post/:session_id" do
    test "200 verified with a valid vp_token, and the session completed", %{conn: conn} do
      ctx = setup_pending_session()
      trust_holder_keys(ctx)

      conn =
        direct_post(conn, ctx.session.id, %{
          "vp_token" => valid_vp_token(ctx),
          "state" => ctx.session.state
        })

      assert json_response(conn, 200) == %{"verification_result" => "verified"}
      assert get_resp_header(conn, "cache-control") == ["no-store"]

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.status == "completed"

      assert_enqueued(
        worker: Sovra.Webhooks.DeliveryJob,
        args: %{"event" => "presentation.verified"}
      )
    end

    test "200 rejected with an invalid vp_token, recording the full tag", %{conn: conn} do
      ctx = setup_pending_session()

      resp =
        conn
        |> direct_post(ctx.session.id, %{
          "vp_token" => "not-a-valid-vp-token",
          "state" => ctx.session.state
        })
        |> json_response(200)

      assert resp == %{"verification_result" => "rejected", "reason" => "invalid_presentation"}

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.status == "failed"
      assert refreshed.error == "malformed_vp_token"

      assert_enqueued(
        worker: Sovra.Webhooks.DeliveryJob,
        args: %{"event" => "presentation.failed"}
      )
    end

    test "200 rejected with a vp_token missing the DCQL credential id", %{conn: conn} do
      ctx = setup_pending_session()
      trust_holder_keys(ctx)

      # Wrong DCQL key — the session asks for "diploma".
      vp =
        Jason.encode!(%{"other_id" => ctx.sd_jwt <> build_kb(ctx.holder_keys, kb_payload(ctx))})

      resp =
        conn
        |> direct_post(ctx.session.id, %{"vp_token" => vp, "state" => ctx.session.state})
        |> json_response(200)

      assert resp == %{"verification_result" => "rejected", "reason" => "invalid_presentation"}

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.status == "failed"
      assert refreshed.error == "malformed_vp_token"
    end

    test "passes an actionable reason through to the holder", %{conn: conn} do
      ctx = setup_pending_session()
      trust_holder_keys(ctx)
      past = DateTime.utc_now() |> DateTime.add(-60) |> DateTime.truncate(:second)
      Sovra.Repo.update!(Ecto.Changeset.change(ctx.session, expires_at: past))

      resp =
        conn
        |> direct_post(ctx.session.id, %{
          "vp_token" => valid_vp_token(ctx),
          "state" => ctx.session.state
        })
        |> json_response(200)

      assert resp == %{"verification_result" => "rejected", "reason" => "session_expired"}
    end

    test "reports a claim the credential lacks without naming it", %{conn: conn} do
      ctx = setup_pending_session([["studentName"], ["gpa"]])
      trust_holder_keys(ctx)

      resp =
        conn
        |> direct_post(ctx.session.id, %{
          "vp_token" => valid_vp_token(ctx),
          "state" => ctx.session.state
        })
        |> json_response(200)

      assert resp == %{"verification_result" => "rejected", "reason" => "request_not_satisfied"}

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.error == "missing_required_claim:gpa"
    end

    test "reports our own dependency failing as a verifier error", %{conn: conn} do
      # No keys installed: the holder DID does not resolve.
      ctx = setup_pending_session()

      resp =
        conn
        |> direct_post(ctx.session.id, %{
          "vp_token" => valid_vp_token(ctx),
          "state" => ctx.session.state
        })
        |> json_response(200)

      assert resp == %{"verification_result" => "rejected", "reason" => "verifier_error"}
    end

    test "200 already_answered when resubmitting against an already-terminal session",
         %{conn: conn} do
      ctx = setup_pending_session()

      # First submission: malformed → session goes to "failed".
      conn
      |> direct_post(ctx.session.id, %{
        "vp_token" => "not-a-valid-vp-token",
        "state" => ctx.session.state
      })
      |> json_response(200)

      {:ok, %{status: "failed", error: original_error}} =
        Verification.get_session(ctx.session.id)

      # Second submission against the same (now terminal) session must not
      # 500, must not overwrite the original outcome, and must not repeat it.
      resp =
        conn
        |> direct_post(ctx.session.id, %{
          "vp_token" => valid_vp_token(ctx),
          "state" => ctx.session.state
        })
        |> json_response(200)

      assert resp == %{"verification_result" => "already_answered"}

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.status == "failed"
      assert refreshed.error == original_error
    end

    test "rejects as session_expired a session the sweeper already expired", %{conn: conn} do
      ctx = setup_pending_session()
      Sovra.Repo.update!(Ecto.Changeset.change(ctx.session, status: "expired"))

      resp =
        conn
        |> direct_post(ctx.session.id, %{
          "vp_token" => valid_vp_token(ctx),
          "state" => ctx.session.state
        })
        |> json_response(200)

      assert resp == %{"verification_result" => "rejected", "reason" => "session_expired"}
    end

    # Transitional: wallets released before the switch to form encoding.
    test "still accepts a JSON body", %{conn: conn} do
      ctx = setup_pending_session()
      trust_holder_keys(ctx)

      resp =
        conn
        |> put_req_header("content-type", "application/json")
        |> post(
          "/wallet/verifier/direct_post/#{ctx.session.id}",
          Jason.encode!(%{"vp_token" => valid_vp_token(ctx), "state" => ctx.session.state})
        )
        |> json_response(200)

      assert resp == %{"verification_result" => "verified"}
    end

    test "415 for a body that is neither form-encoded nor JSON", %{conn: conn} do
      ctx = setup_pending_session()

      resp =
        conn
        |> put_req_header("content-type", "text/plain")
        |> post("/wallet/verifier/direct_post/#{ctx.session.id}", "vp_token=x")
        |> json_response(415)

      assert resp == %{"error" => "unsupported_media_type"}

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.status == "pending"
    end

    test "404 when session id doesn't match the state", %{conn: conn} do
      ctx = setup_pending_session()

      resp =
        conn
        |> direct_post(Ecto.UUID.generate(), %{
          "vp_token" => valid_vp_token(ctx),
          "state" => ctx.session.state
        })
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end

    test "404 when state is unknown", %{conn: conn} do
      resp =
        conn
        |> direct_post(Ecto.UUID.generate(), %{
          "vp_token" => "anything",
          "state" => "unknown-state-#{System.unique_integer([:positive])}"
        })
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end

    test "400 when vp_token is missing", %{conn: conn} do
      ctx = setup_pending_session()

      resp =
        conn
        |> direct_post(ctx.session.id, %{"state" => ctx.session.state})
        |> json_response(400)

      assert resp == %{"error" => "missing_vp_token"}
    end

    test "400 when state is missing", %{conn: conn} do
      ctx = setup_pending_session()

      resp =
        conn
        |> direct_post(ctx.session.id, %{"vp_token" => "x"})
        |> json_response(400)

      assert resp == %{"error" => "missing_state"}
    end
  end
end
