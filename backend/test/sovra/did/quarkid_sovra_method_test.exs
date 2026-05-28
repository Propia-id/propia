defmodule Sovra.DID.QuarkidSovraMethodTest do
  use ExUnit.Case, async: false

  alias Sovra.DID.QuarkidSovraMethod

  # Verbatim DID Document body returned by https://node.sovra.io/resolve/<did>
  # for the holder used in the integration spec (~/Downloads/VCs.md §4.1).
  @spec_did "did:quarkid:sovra:EiAKOd9MWl6Mr-FPod_0AJQhWgwv4ppJntUmCd43KrCikg"
  @spec_doc %{
    "@context" => [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      %{"@vocab" => "https://www.w3.org/ns/did#"}
    ],
    "id" => @spec_did,
    "verificationMethod" => [
      %{
        "id" => "#didcomm",
        "controller" => @spec_did,
        "type" => "X25519KeyAgreementKey2019",
        "publicKeyJwk" => %{
          "kty" => "OKP",
          "crv" => "X25519",
          "x" => "_nuFITfGqogup09SMiehtKfMnRfS3XdrSrTXY65Uw0A"
        }
      },
      %{
        "id" => "#vc",
        "controller" => @spec_did,
        "type" => "Ed25519VerificationKey2018",
        "publicKeyJwk" => %{
          "kty" => "OKP",
          "crv" => "Ed25519",
          "x" => "_9OGRsEIBEL6OhDqsbVat8Ad2fCNjuabp93SyOVkM7U"
        }
      }
    ],
    "keyAgreement" => ["#didcomm"],
    "assertionMethod" => ["#vc"]
  }

  setup do
    :ets.delete_all_objects(:sovra_did_document_cache)

    Application.put_env(:sovra, :quarkid_resolver,
      base_url: "https://node.sovra.io/resolve/",
      request_timeout_ms: 5_000,
      doc_cache_ttl_s: 300,
      negative_cache_ttl_s: 30,
      req_opts: [plug: {Req.Test, :sovra_quarkid_resolver}, retry: false]
    )

    on_exit(fn ->
      Application.put_env(:sovra, :quarkid_resolver,
        base_url: "https://node.sovra.io/resolve/",
        request_timeout_ms: 5_000,
        doc_cache_ttl_s: 300,
        negative_cache_ttl_s: 30
      )
    end)

    :ok
  end

  describe "resolve/1 — happy path" do
    test "returns the Ed25519 JWK from the verbatim spec DID Document" do
      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        assert conn.request_path =~ @spec_did
        Req.Test.json(conn, @spec_doc)
      end)

      assert {:ok, [jwk]} = QuarkidSovraMethod.resolve(@spec_did)

      assert jwk.kty == "OKP"
      assert jwk.crv == "Ed25519"
      assert byte_size(jwk.x) == 32

      expected = Base.url_decode64!("_9OGRsEIBEL6OhDqsbVat8Ad2fCNjuabp93SyOVkM7U", padding: false)
      assert jwk.x == expected
    end

    test "filters out X25519 key-agreement entries" do
      # Construct a doc with only the key-agreement entry — should be empty after filtering.
      doc_no_signing =
        Map.put(@spec_doc, "verificationMethod", [
          Enum.find(@spec_doc["verificationMethod"], &(&1["type"] == "X25519KeyAgreementKey2019"))
        ])

      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        Req.Test.json(conn, doc_no_signing)
      end)

      assert {:error, :did_unresolvable} = QuarkidSovraMethod.resolve(@spec_did)
    end

    test "tolerates an envelope-wrapped {didDocument: ...} response" do
      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        Req.Test.json(conn, %{"didDocument" => @spec_doc})
      end)

      assert {:ok, [%{crv: "Ed25519"}]} = QuarkidSovraMethod.resolve(@spec_did)
    end

    test "accepts publicKeyJwk.x with base64url padding" do
      expected = Base.url_decode64!("_9OGRsEIBEL6OhDqsbVat8Ad2fCNjuabp93SyOVkM7U", padding: false)
      padded_x = Base.url_encode64(expected, padding: true)
      assert String.ends_with?(padded_x, "=")

      doc_with_padded_x =
        Map.put(@spec_doc, "verificationMethod", [
          %{
            "id" => "#vc",
            "type" => "Ed25519VerificationKey2018",
            "publicKeyJwk" => %{"kty" => "OKP", "crv" => "Ed25519", "x" => padded_x}
          }
        ])

      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        Req.Test.json(conn, doc_with_padded_x)
      end)

      assert {:ok, [jwk]} = QuarkidSovraMethod.resolve(@spec_did)
      assert jwk.x == expected
    end
  end

  describe "resolve/1 — failures" do
    test "404 → :did_unresolvable" do
      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        Plug.Conn.send_resp(conn, 404, "")
      end)

      assert {:error, :did_unresolvable} = QuarkidSovraMethod.resolve(@spec_did)
    end

    test "malformed JSON body → :did_unresolvable" do
      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, "<<not json>>")
      end)

      assert {:error, :did_unresolvable} = QuarkidSovraMethod.resolve(@spec_did)
    end

    test "empty verificationMethod array → :did_unresolvable" do
      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        Req.Test.json(conn, %{"id" => @spec_did, "verificationMethod" => []})
      end)

      assert {:error, :did_unresolvable} = QuarkidSovraMethod.resolve(@spec_did)
    end

    test "transport error → :did_unresolvable" do
      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        Req.Test.transport_error(conn, :timeout)
      end)

      assert {:error, :did_unresolvable} = QuarkidSovraMethod.resolve(@spec_did)
    end

    test "syntactic-invalid DID (empty suffix) → :invalid_did" do
      assert {:error, :invalid_did} = QuarkidSovraMethod.resolve("did:quarkid:sovra:")
    end

    test "syntactic-invalid DID (illegal characters) → :invalid_did" do
      assert {:error, :invalid_did} = QuarkidSovraMethod.resolve("did:quarkid:sovra:has spaces")
    end

    test "wrong method prefix → :unsupported_did_method" do
      assert {:error, :unsupported_did_method} = QuarkidSovraMethod.resolve("did:other:abc")
    end
  end

  describe "caching" do
    test "second call within TTL doesn't re-hit the resolver" do
      counter = :counters.new(1, [])

      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        :counters.add(counter, 1, 1)
        Req.Test.json(conn, @spec_doc)
      end)

      assert {:ok, [_]} = QuarkidSovraMethod.resolve(@spec_did)
      assert {:ok, [_]} = QuarkidSovraMethod.resolve(@spec_did)
      assert :counters.get(counter, 1) == 1
    end

    test "negative results are also cached" do
      counter = :counters.new(1, [])

      Req.Test.stub(:sovra_quarkid_resolver, fn conn ->
        :counters.add(counter, 1, 1)
        Plug.Conn.send_resp(conn, 404, "")
      end)

      assert {:error, :did_unresolvable} = QuarkidSovraMethod.resolve(@spec_did)
      assert {:error, :did_unresolvable} = QuarkidSovraMethod.resolve(@spec_did)
      assert :counters.get(counter, 1) == 1
    end
  end
end
