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
  end

  defmodule StubResolver do
    def resolve(_did) do
      case Application.get_env(:sovra, {__MODULE__, :keys}) do
        keys when is_list(keys) and keys != [] -> {:ok, keys}
        _ -> {:error, :did_unresolvable}
      end
    end
  end

  defp create_workspace(name), do: provision_workspace(fixture_workspace(name: name).workspace)

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

  defp setup_pending_session do
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
          "claims" => [%{"path" => ["studentName"]}]
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
    payload = %{
      "iss" => ctx.holder_did,
      "aud" => "verifier:#{ctx.verifier_ws.id}",
      "nonce" => ctx.session.nonce,
      "iat" => System.system_time(:second),
      "sd_hash" => ctx.sd_hash
    }

    ctx.sd_jwt <> build_kb(ctx.holder_keys, payload)
  end

  describe "POST /api/v1/verify/direct_post/:session_id" do
    test "200 with a valid vp_token marks the session completed", %{conn: conn} do
      ctx = setup_pending_session()

      Application.put_env(:sovra, {StubResolver, :keys}, [
        %{kty: "EC", crv: "P-256", x: ctx.holder_keys.x, y: ctx.holder_keys.y}
      ])

      vp = valid_vp_token(ctx)

      _resp =
        conn
        |> post("/api/v1/verify/direct_post/#{ctx.session.id}", %{
          "vp_token" => vp,
          "state" => ctx.session.state
        })
        |> json_response(200)

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.status == "completed"

      assert_enqueued(
        worker: Sovra.Webhooks.DeliveryJob,
        args: %{"event" => "presentation.verified"}
      )
    end

    test "200 with an invalid vp_token records a failure (no 4xx to wallet)", %{conn: conn} do
      ctx = setup_pending_session()

      _resp =
        conn
        |> post("/api/v1/verify/direct_post/#{ctx.session.id}", %{
          "vp_token" => "not-a-valid-vp-token",
          "state" => ctx.session.state
        })
        |> json_response(200)

      {:ok, refreshed} = Verification.get_session(ctx.session.id)
      assert refreshed.status == "failed"
      assert refreshed.error == "malformed_vp_token"

      assert_enqueued(
        worker: Sovra.Webhooks.DeliveryJob,
        args: %{"event" => "presentation.failed"}
      )
    end

    test "404 when session id doesn't match the state", %{conn: conn} do
      ctx = setup_pending_session()
      vp = valid_vp_token(ctx)

      resp =
        conn
        |> post("/api/v1/verify/direct_post/#{Ecto.UUID.generate()}", %{
          "vp_token" => vp,
          "state" => ctx.session.state
        })
        |> json_response(404)

      assert resp == %{"error" => "session_not_found"}
    end

    test "404 when state is unknown", %{conn: conn} do
      resp =
        conn
        |> post("/api/v1/verify/direct_post/#{Ecto.UUID.generate()}", %{
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
        |> post("/api/v1/verify/direct_post/#{ctx.session.id}", %{"state" => ctx.session.state})
        |> json_response(400)

      assert resp == %{"error" => "missing_vp_token"}
    end

    test "400 when state is missing", %{conn: conn} do
      ctx = setup_pending_session()

      resp =
        conn
        |> post("/api/v1/verify/direct_post/#{ctx.session.id}", %{"vp_token" => "x"})
        |> json_response(400)

      assert resp == %{"error" => "missing_state"}
    end
  end
end
