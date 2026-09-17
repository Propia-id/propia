defmodule Sovra.IssuerTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Issuer
  alias Sovra.Issuer.CredentialOffer
  alias Sovra.Issuer.TokenHash
  alias Sovra.Crypto.P256
  alias Sovra.Organizations.Organization
  alias Sovra.Webhooks.DeliveryJob
  alias Sovra.Workspaces

  setup do
    # Ensure SoftwareKeyStore is running
    :ok
  end

  defp create_test_user, do: fixture_user()
  defp create_test_issuer, do: provision_workspace(fixture_workspace().workspace)

  defp create_test_schema(issuer, opts \\ []) do
    attrs = %{
      schema_id: "test-schema-#{System.unique_integer([:positive])}",
      credential_type: "TestCredential",
      name: "Test Credential",
      claims: [
        %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true},
        %{"key" => "age", "type" => "integer", "required" => false, "disclosable" => true}
      ],
      validity_period: Keyword.get(opts, :validity_period, "1y")
    }

    {:ok, schema} = Issuer.create_schema(issuer.id, attrs)
    schema
  end

  defp holder_proof_jwt(c_nonce) do
    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

    header = %{
      "typ" => "openid4vci-proof+jwt",
      "alg" => "ES256",
      "jwk" => %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => Base.url_encode64(x, padding: false),
        "y" => Base.url_encode64(y, padding: false)
      }
    }

    payload = %{"iss" => "did:sovra:0xholder", "nonce" => c_nonce}
    header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
    payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
    signing_input = "#{header_b64}.#{payload_b64}"
    hash = :crypto.hash(:sha256, signing_input)
    {:ok, %{r: r, s: s}} = P256.sign(hash, priv)
    raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
    sig_b64 = Base.url_encode64(raw_sig, padding: false)

    %{"proof_type" => "jwt", "jwt" => "#{signing_input}.#{sig_b64}"}
  end

  defp jwt_payload(sd_jwt) do
    [jwt | _] = String.split(sd_jwt, "~")
    [_, payload_b64 | _] = String.split(jwt, ".")
    payload_b64 |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  describe "schemas without a validity period" do
    test "a schema may omit validity_period entirely" do
      issuer = create_test_issuer()

      {:ok, schema} =
        Issuer.create_schema(issuer.id, %{
          schema_id: "no-expiry-#{System.unique_integer([:positive])}",
          credential_type: "NoExpiryCredential",
          name: "No Expiry",
          claims: [
            %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true}
          ],
          validity_period: nil
        })

      assert schema.validity_period == nil
    end

    test "an unparseable validity_period is rejected rather than defaulted" do
      issuer = create_test_issuer()

      assert {:error, changeset} =
               Issuer.create_schema(issuer.id, %{
                 schema_id: "bad-#{System.unique_integer([:positive])}",
                 credential_type: "BadCredential",
                 name: "Bad",
                 claims: [
                   %{
                     "key" => "name",
                     "type" => "string",
                     "required" => true,
                     "disclosable" => true
                   }
                 ],
                 validity_period: "1yr"
               })

      assert %{validity_period: ["has invalid format"]} = errors_on(changeset)
    end

    test "the offer preview carries no exp" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer, validity_period: nil)

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      refute Map.has_key?(result.credential, "exp")
      assert Map.has_key?(result.credential, "iat")
    end

    test "the issued SD-JWT carries no exp and the row records no expiry" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer, validity_period: nil)

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      {:ok, token_data} = Issuer.exchange_token(result.pre_authorized_code)

      {:ok, %{credential: sd_jwt, format: "vc+sd-jwt"}} =
        Issuer.issue_credential(
          token_data.access_token,
          schema.credential_type,
          holder_proof_jwt(token_data.c_nonce)
        )

      payload = jwt_payload(sd_jwt)
      refute Map.has_key?(payload, "exp")
      assert is_integer(payload["iat"])

      issued = Repo.get_by!(Sovra.Issuer.IssuedCredential, id: result.offer.id)
      assert issued.expires_at == nil
      assert issued.issued_at != nil
    end

    test "a schema that sets a validity period still stamps exp" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer, validity_period: "1y")

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      {:ok, token_data} = Issuer.exchange_token(result.pre_authorized_code)

      {:ok, %{credential: sd_jwt, format: "vc+sd-jwt"}} =
        Issuer.issue_credential(
          token_data.access_token,
          schema.credential_type,
          holder_proof_jwt(token_data.c_nonce)
        )

      payload = jwt_payload(sd_jwt)
      assert is_integer(payload["exp"])
      assert payload["exp"] > payload["iat"]

      issued = Repo.get_by!(Sovra.Issuer.IssuedCredential, id: result.offer.id)
      assert issued.expires_at != nil
    end
  end

  describe "Workspaces.create_workspace/3" do
    test "creates workspace with proper EOA address derived from secp256k1 keypair" do
      user = create_test_user()

      {:ok, org} =
        %{name: "Org #{System.unique_integer([:positive])}"}
        |> Organization.create_changeset()
        |> Repo.insert()

      {:ok, %{workspace: issuer, webhook_secret: webhook_secret}} =
        Workspaces.create_workspace(org.id, %{name: "New Issuer"}, user.id)

      issuer = provision_workspace(issuer)

      assert issuer.name == "New Issuer"
      assert String.starts_with?(issuer.eoa_address, "0x")
      assert String.length(issuer.eoa_address) == 42
      assert String.starts_with?(issuer.did, "did:sovra:0x")
      assert issuer.status == "active"
      refute String.starts_with?(issuer.eoa_key_id, "stub_")
      assert issuer.organization_id == org.id
      assert is_binary(webhook_secret) and String.starts_with?(webhook_secret, "whsec_")
    end
  end

  describe "create_credential_offer/3" do
    test "stores hashed pre_authorized_code, returns plaintext" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)
      claims = %{"name" => "Alice"}

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, claims)

      assert is_binary(result.pre_authorized_code)
      offer = Repo.get!(CredentialOffer, result.offer.id)
      assert offer.pre_authorized_code_hash == TokenHash.hash(result.pre_authorized_code)
      assert is_nil(offer.access_token_hash)
    end

    test "returns offer_uri with plaintext code" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)
      claims = %{"name" => "Alice"}

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, claims)

      assert String.contains?(result.offer_uri, result.pre_authorized_code)
    end

    test "returns a preliminary VC without holder-bound fields or proof" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)
      claims = %{"name" => "Alice", "age" => 30, "ignored" => "drop-me"}

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, claims)

      preview = result.credential
      assert preview["iss"] == "#{Sovra.Issuer.ClaimUtils.base_url()}/#{issuer.did}"
      assert preview["vct"] == schema.credential_type
      assert preview["name"] == "Alice"
      assert preview["age"] == 30
      assert is_integer(preview["iat"])
      assert preview["exp"] > preview["iat"]
      assert is_list(preview["credentialStatus"])
      refute Map.has_key?(preview, "ignored")
      refute Map.has_key?(preview, "sub")
      refute Map.has_key?(preview, "cnf")
      refute Map.has_key?(preview, "_sd")
    end
  end

  describe "status list index allocation (HMAC)" do
    alias Sovra.Crypto.HmacKeyStore

    test "index lies in [0, 131_071] and is keyed off the dedicated workspace HMAC key" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      idx = result.offer.status_list_index
      assert is_integer(idx)
      assert idx >= 0 and idx <= 131_071

      # The index must be deterministic from the offer id + the workspace's
      # status-index HMAC key (NOT the webhook key). Recompute and compare.
      assert {:ok, mac} =
               HmacKeyStore.hmac(
                 issuer.status_index_secret_key_id,
                 "sovra:status-index:revocation:#{result.offer.id}:0"
               )

      <<expected::unsigned-big-integer-size(17), _rest::bitstring>> = mac
      assert idx == expected
    end

    test "indices derived under the webhook key disagree with the actual allocation" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      assert {:ok, mac_status} =
               HmacKeyStore.hmac(
                 issuer.status_index_secret_key_id,
                 "sovra:status-index:revocation:#{result.offer.id}:0"
               )

      assert {:ok, mac_webhook} =
               HmacKeyStore.hmac(
                 issuer.webhook_secret_key_id,
                 "sovra:status-index:revocation:#{result.offer.id}:0"
               )

      # Domain separation: the two keys must not produce the same MAC.
      refute mac_status == mac_webhook
    end

    test "1000 distinct offers yield mostly distinct indices (no pathological collisions)" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      indices =
        for _ <- 1..1_000 do
          {:ok, result} =
            Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

          result.offer.status_list_index
        end

      # All inserts succeeded ⇒ they are unique by virtue of the unique constraint.
      assert length(Enum.uniq(indices)) == 1_000
      # Sanity: spread across the bitmap, not clustered near zero.
      assert Enum.max(indices) - Enum.min(indices) > 50_000
    end
  end

  describe "exchange_token/2" do
    setup do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      %{offer_result: result}
    end

    test "exchanges valid code for hashed access token", %{offer_result: result} do
      {:ok, token_data} = Issuer.exchange_token(result.pre_authorized_code)
      assert is_binary(token_data.access_token)
      assert is_binary(token_data.c_nonce)
      assert token_data.c_nonce_expires_in == 86400
      assert token_data.expires_in == 86400

      offer = Repo.get!(CredentialOffer, result.offer.id)
      assert offer.access_token_hash == TokenHash.hash(token_data.access_token)
      assert offer.status == "token_exchanged"
    end

    test "rejects invalid code" do
      assert {:error, :invalid_code} = Issuer.exchange_token("nonexistent-code")
    end

    test "rejects already-used code", %{offer_result: result} do
      {:ok, _} = Issuer.exchange_token(result.pre_authorized_code)
      assert {:error, :code_already_used} = Issuer.exchange_token(result.pre_authorized_code)
    end
  end

  describe "issue_credential/3 with proof verification" do
    setup do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, offer_result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      {:ok, token_data} = Issuer.exchange_token(offer_result.pre_authorized_code)

      %{
        offer_result: offer_result,
        token_data: token_data,
        issuer: issuer,
        schema: schema
      }
    end

    test "rejects proof with missing proof_type", %{token_data: token_data} do
      assert {:error, :invalid_proof} =
               Issuer.issue_credential(token_data.access_token, "TestCredential", %{
                 "jwt" => "anything"
               })
    end

    test "rejects proof with unsupported proof_type", %{token_data: token_data} do
      assert {:error, :invalid_proof} =
               Issuer.issue_credential(token_data.access_token, "TestCredential", %{
                 "proof_type" => "cwt",
                 "jwt" => "anything"
               })
    end

    test "rejects request with missing credential_configuration_id", %{token_data: token_data} do
      assert {:error, :invalid_credential_request} =
               Issuer.issue_credential(token_data.access_token, nil, %{
                 "proof_type" => "jwt",
                 "jwt" => "anything"
               })
    end

    test "rejects request when credential_configuration_id does not match the offer", %{
      token_data: token_data
    } do
      assert {:error, :invalid_credential_request} =
               Issuer.issue_credential(token_data.access_token, "WrongCredential", %{
                 "proof_type" => "jwt",
                 "jwt" => "anything"
               })
    end

    test "rejects proof with invalid signature", %{token_data: token_data} do
      # Build a proof JWT with wrong signature
      {:ok, %{public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

      header = %{
        "typ" => "openid4vci-proof+jwt",
        "alg" => "ES256",
        "jwk" => %{
          "kty" => "EC",
          "crv" => "P-256",
          "x" => Base.url_encode64(x, padding: false),
          "y" => Base.url_encode64(y, padding: false)
        }
      }

      payload = %{"iss" => "did:sovra:0xholder", "nonce" => token_data.c_nonce}

      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      # Use garbage signature
      fake_sig = Base.url_encode64(:crypto.strong_rand_bytes(64), padding: false)
      jwt = "#{header_b64}.#{payload_b64}.#{fake_sig}"

      proof = %{"proof_type" => "jwt", "jwt" => jwt}

      assert {:error, :invalid_proof} =
               Issuer.issue_credential(token_data.access_token, "TestCredential", proof)
    end

    test "accepts proof with valid P-256 signature and binds holder DID", %{
      token_data: token_data
    } do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
      holder_did = "did:sovra:0xholder123"

      header = %{
        "typ" => "openid4vci-proof+jwt",
        "alg" => "ES256",
        "jwk" => %{
          "kty" => "EC",
          "crv" => "P-256",
          "x" => Base.url_encode64(x, padding: false),
          "y" => Base.url_encode64(y, padding: false)
        }
      }

      payload = %{"iss" => holder_did, "nonce" => token_data.c_nonce}

      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      signing_input = "#{header_b64}.#{payload_b64}"
      hash = :crypto.hash(:sha256, signing_input)

      {:ok, %{r: r, s: s}} = P256.sign(hash, priv)
      raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
      sig_b64 = Base.url_encode64(raw_sig, padding: false)
      jwt = "#{signing_input}.#{sig_b64}"

      proof = %{"proof_type" => "jwt", "jwt" => jwt}

      assert {:ok, %{credential: sd_jwt, format: "vc+sd-jwt"}} =
               Issuer.issue_credential(token_data.access_token, "TestCredential", proof)

      assert is_binary(sd_jwt)
      assert String.contains?(sd_jwt, "~")

      # Verify the SD-JWT has the correct holder DID as sub
      [jwt_part | _] = String.split(sd_jwt, "~")
      [_, payload_b64 | _] = String.split(jwt_part, ".")
      {:ok, payload_json} = Base.url_decode64(payload_b64, padding: false)
      {:ok, jwt_payload} = Jason.decode(payload_json)
      assert jwt_payload["sub"] == holder_did

      assert_enqueued(
        worker: DeliveryJob,
        args: %{
          "event" => "credential.issued",
          "payload" => %{
            "data" => %{
              "credential" => sd_jwt,
              "format" => "vc+sd-jwt",
              "holder_did" => holder_did
            }
          }
        }
      )
    end

    test "accepts a WebAuthn passkey proof and binds holder DID", %{token_data: token_data} do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()
      holder_did = "did:sovra:0xalignedholder"

      header = %{
        "typ" => "openid4vci-proof+jwt",
        "alg" => "WebAuthn",
        "jwk" => %{
          "kty" => "EC",
          "crv" => "P-256",
          "x" => Base.url_encode64(x, padding: false),
          "y" => Base.url_encode64(y, padding: false)
        }
      }

      payload = %{"iss" => holder_did, "nonce" => token_data.c_nonce}
      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      signing_input = "#{header_b64}.#{payload_b64}"

      # The passkey signs sha256(signing_input) as its WebAuthn challenge.
      digest = :crypto.hash(:sha256, signing_input)
      challenge_b64 = Base.url_encode64(digest, padding: false)

      cdj =
        ~s({"type":"webauthn.get","challenge":") <>
          challenge_b64 <> ~s(","origin":"https://wallet.example"})

      auth_data = :crypto.strong_rand_bytes(32) <> <<0x05>> <> <<0, 0, 0, 1>>
      message_hash = :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, cdj))
      {:ok, %{r: r, s: s}} = P256.sign(message_hash, priv)

      assertion =
        Jason.encode!(%{
          "r" => "0x" <> Base.encode16(P256.pad_or_trim(r, 32), case: :lower),
          "s" => "0x" <> Base.encode16(P256.pad_or_trim(s, 32), case: :lower),
          "challenge_index" => :binary.match(cdj, ~s("challenge":")) |> elem(0),
          "type_index" => :binary.match(cdj, ~s("type":"webauthn.get")) |> elem(0),
          "authenticator_data" => "0x" <> Base.encode16(auth_data, case: :lower),
          "client_data_json" => cdj
        })

      jwt = "#{signing_input}.#{Base.url_encode64(assertion, padding: false)}"
      proof = %{"proof_type" => "jwt", "jwt" => jwt}

      assert {:ok, %{credential: sd_jwt, format: "vc+sd-jwt"}} =
               Issuer.issue_credential(token_data.access_token, "TestCredential", proof)

      [jwt_part | _] = String.split(sd_jwt, "~")
      [_, cred_payload_b64 | _] = String.split(jwt_part, ".")
      {:ok, cred_payload_json} = Base.url_decode64(cred_payload_b64, padding: false)
      {:ok, cred_payload} = Jason.decode(cred_payload_json)
      assert cred_payload["sub"] == holder_did
    end

    test "issued credential reuses the offer id", %{token_data: token_data, offer_result: result} do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

      header = %{
        "typ" => "openid4vci-proof+jwt",
        "alg" => "ES256",
        "jwk" => %{
          "kty" => "EC",
          "crv" => "P-256",
          "x" => Base.url_encode64(x, padding: false),
          "y" => Base.url_encode64(y, padding: false)
        }
      }

      payload = %{"iss" => "did:sovra:0xholder", "nonce" => token_data.c_nonce}
      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      signing_input = "#{header_b64}.#{payload_b64}"
      hash = :crypto.hash(:sha256, signing_input)
      {:ok, %{r: r, s: s}} = P256.sign(hash, priv)
      raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
      sig_b64 = Base.url_encode64(raw_sig, padding: false)
      jwt = "#{signing_input}.#{sig_b64}"

      {:ok, _sd_jwt} =
        Issuer.issue_credential(token_data.access_token, "TestCredential", %{
          "proof_type" => "jwt",
          "jwt" => jwt
        })

      issued = Sovra.Repo.get_by!(Sovra.Issuer.IssuedCredential, id: result.offer.id)
      assert issued.id == result.offer.id
    end

    test "rejects proof with wrong nonce", %{token_data: token_data} do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

      header = %{
        "typ" => "openid4vci-proof+jwt",
        "alg" => "ES256",
        "jwk" => %{
          "kty" => "EC",
          "crv" => "P-256",
          "x" => Base.url_encode64(x, padding: false),
          "y" => Base.url_encode64(y, padding: false)
        }
      }

      payload = %{"iss" => "did:sovra:0xholder", "nonce" => "wrong-nonce"}

      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      signing_input = "#{header_b64}.#{payload_b64}"
      hash = :crypto.hash(:sha256, signing_input)

      {:ok, %{r: r, s: s}} = P256.sign(hash, priv)
      raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
      sig_b64 = Base.url_encode64(raw_sig, padding: false)
      jwt = "#{signing_input}.#{sig_b64}"

      proof = %{"proof_type" => "jwt", "jwt" => jwt}

      assert {:error, :invalid_proof} =
               Issuer.issue_credential(token_data.access_token, "TestCredential", proof)
    end

    test "rejects proof missing iss claim", %{token_data: token_data} do
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

      header = %{
        "typ" => "openid4vci-proof+jwt",
        "alg" => "ES256",
        "jwk" => %{
          "kty" => "EC",
          "crv" => "P-256",
          "x" => Base.url_encode64(x, padding: false),
          "y" => Base.url_encode64(y, padding: false)
        }
      }

      # No "iss" field
      payload = %{"nonce" => token_data.c_nonce}

      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      signing_input = "#{header_b64}.#{payload_b64}"
      hash = :crypto.hash(:sha256, signing_input)

      {:ok, %{r: r, s: s}} = P256.sign(hash, priv)
      raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
      sig_b64 = Base.url_encode64(raw_sig, padding: false)
      jwt = "#{signing_input}.#{sig_b64}"

      proof = %{"proof_type" => "jwt", "jwt" => jwt}

      assert {:error, :invalid_proof} =
               Issuer.issue_credential(token_data.access_token, "TestCredential", proof)
    end
  end

  describe "credential delivery clears sensitive data" do
    test "claims and token hashes are cleared after issuance" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, offer_result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      {:ok, token_data} = Issuer.exchange_token(offer_result.pre_authorized_code)

      # Build valid proof
      {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

      header = %{
        "typ" => "openid4vci-proof+jwt",
        "alg" => "ES256",
        "jwk" => %{
          "kty" => "EC",
          "crv" => "P-256",
          "x" => Base.url_encode64(x, padding: false),
          "y" => Base.url_encode64(y, padding: false)
        }
      }

      payload = %{"iss" => "did:sovra:0xholder", "nonce" => token_data.c_nonce}
      header_b64 = Base.url_encode64(Jason.encode!(header), padding: false)
      payload_b64 = Base.url_encode64(Jason.encode!(payload), padding: false)
      signing_input = "#{header_b64}.#{payload_b64}"
      hash = :crypto.hash(:sha256, signing_input)
      {:ok, %{r: r, s: s}} = P256.sign(hash, priv)
      raw_sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)
      sig_b64 = Base.url_encode64(raw_sig, padding: false)
      jwt = "#{signing_input}.#{sig_b64}"

      {:ok, _sd_jwt} =
        Issuer.issue_credential(token_data.access_token, "TestCredential", %{
          "proof_type" => "jwt",
          "jwt" => jwt
        })

      # Verify sensitive data is cleared
      offer = Repo.get!(CredentialOffer, offer_result.offer.id)
      assert offer.status == "issued"
      assert is_nil(offer.claims)
      assert is_nil(offer.pre_authorized_code_hash)
      assert is_nil(offer.access_token_hash)
    end
  end

  describe "credential designs" do
    defp sample_design_attrs do
      %{
        name: "Test Design",
        description: "A test design",
        display: %{
          title: %{text: "My Credential"},
          subtitle: %{path: ["$.name"], fallback: "Unnamed"},
          properties: [
            %{path: ["$.name"], label: "Name", fallback: "—"},
            %{path: ["$.age"], label: "Age", fallback: "—"}
          ]
        },
        styles: %{
          thumbnail: %{uri: "https://example.com/logo.png", alt: "logo"},
          background: %{color: "#1a365d"},
          text: %{color: "#ffffff"}
        }
      }
    end

    test "upsert_design creates a new design" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, design} = Issuer.upsert_design(issuer.id, schema.schema_id, sample_design_attrs())

      assert design.name == "Test Design"
      assert design.version == 1
      assert design.credential_schema_id == schema.id
      assert design.display.title.text == "My Credential"
      assert design.styles.background.color == "#1a365d"
      assert length(design.display.properties) == 2
    end

    test "upsert_design accepts string-keyed attrs (from controller)" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      attrs = %{
        "name" => "DNI",
        "description" => nil,
        "back" => nil,
        "display" => %{
          "title" => %{"text" => "DNI"},
          "subtitle" => %{"text" => "Documento Nacional de Identidad"},
          "properties" => [%{"label" => "Nombre", "path" => ["$.name"]}]
        },
        "styles" => %{
          "background" => %{"color" => "#1a365d"},
          "text" => %{"color" => "#ffffff"}
        }
      }

      assert {:ok, design} = Issuer.upsert_design(issuer.id, schema.schema_id, attrs)
      assert design.name == "DNI"
      assert design.display.title.text == "DNI"
    end

    test "upsert_design updates an existing design and bumps version" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, design1} = Issuer.upsert_design(issuer.id, schema.schema_id, sample_design_attrs())
      assert design1.version == 1

      updated_attrs =
        sample_design_attrs()
        |> put_in([:styles, :background, :color], "#000000")

      {:ok, design2} = Issuer.upsert_design(issuer.id, schema.schema_id, updated_attrs)

      assert design2.id == design1.id
      assert design2.version == 2
      assert design2.styles.background.color == "#000000"
    end

    test "upsert_design returns error for missing schema" do
      issuer = create_test_issuer()

      assert {:error, :schema_not_found} =
               Issuer.upsert_design(issuer.id, "nonexistent", sample_design_attrs())
    end

    test "upsert_design rejects non-hex colors" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      attrs = put_in(sample_design_attrs(), [:styles, :background, :color], "blue")

      assert {:error, %Ecto.Changeset{}} =
               Issuer.upsert_design(issuer.id, schema.schema_id, attrs)
    end

    test "upsert_design rejects properties referencing unknown claims" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      attrs =
        put_in(sample_design_attrs(), [:display, :properties], [
          %{path: ["$.unknown_field"], label: "Unknown"}
        ])

      assert {:error, %Ecto.Changeset{} = cs} =
               Issuer.upsert_design(issuer.id, schema.schema_id, attrs)

      errors = Ecto.Changeset.traverse_errors(cs, fn {msg, _} -> msg end)
      assert Map.has_key?(errors, :display)
    end

    test "upsert_design rejects DisplayMapping with neither text nor path" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      attrs = put_in(sample_design_attrs(), [:display, :title], %{fallback: "x"})

      assert {:error, %Ecto.Changeset{}} =
               Issuer.upsert_design(issuer.id, schema.schema_id, attrs)
    end

    test "get_design returns the design" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)
      {:ok, _design} = Issuer.upsert_design(issuer.id, schema.schema_id, sample_design_attrs())

      {:ok, design} = Issuer.get_design(issuer.id, schema.schema_id)
      assert design.name == "Test Design"
      assert design.credential_schema.id == schema.id
    end

    test "get_design returns design_not_found when missing" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      assert {:error, :design_not_found} = Issuer.get_design(issuer.id, schema.schema_id)
    end

    test "tenants cannot access each other's designs" do
      issuer_a = create_test_issuer()
      issuer_b = create_test_issuer()
      schema_a = create_test_schema(issuer_a)

      {:ok, _design} =
        Issuer.upsert_design(issuer_a.id, schema_a.schema_id, sample_design_attrs())

      assert {:error, :schema_not_found} =
               Issuer.get_design(issuer_b.id, schema_a.schema_id)

      assert {:error, :schema_not_found} =
               Issuer.upsert_design(issuer_b.id, schema_a.schema_id, sample_design_attrs())

      assert {:error, :schema_not_found} =
               Issuer.delete_design(issuer_b.id, schema_a.schema_id)
    end

    test "delete_design removes the design" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)
      {:ok, _} = Issuer.upsert_design(issuer.id, schema.schema_id, sample_design_attrs())

      assert {:ok, _} = Issuer.delete_design(issuer.id, schema.schema_id)
      assert {:error, :design_not_found} = Issuer.get_design(issuer.id, schema.schema_id)
    end

    test "list_designs returns only designs for the given issuer" do
      issuer_a = create_test_issuer()
      issuer_b = create_test_issuer()
      schema_a = create_test_schema(issuer_a)
      schema_b = create_test_schema(issuer_b)

      {:ok, _} = Issuer.upsert_design(issuer_a.id, schema_a.schema_id, sample_design_attrs())
      {:ok, _} = Issuer.upsert_design(issuer_b.id, schema_b.schema_id, sample_design_attrs())

      designs = Issuer.list_designs(issuer_a.id)
      assert length(designs) == 1
      assert hd(designs).credential_schema_id == schema_a.id
    end

    test "schema deletion cascades to design" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)
      {:ok, _} = Issuer.upsert_design(issuer.id, schema.schema_id, sample_design_attrs())

      {:ok, _} = Issuer.delete_schema(issuer.id, schema.id)

      assert Sovra.Repo.get_by(Sovra.Issuer.CredentialDesign, credential_schema_id: schema.id) ==
               nil
    end

    test "back section is optional and stored when provided" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      attrs =
        Map.put(sample_design_attrs(), :back, %{
          display: %{
            properties: [%{path: ["$.age"], label: "Age"}]
          },
          styles: %{
            background: %{color: "#222222"},
            text: %{color: "#eeeeee"}
          }
        })

      {:ok, design} = Issuer.upsert_design(issuer.id, schema.schema_id, attrs)

      assert design.back.styles.background.color == "#222222"
      assert length(design.back.display.properties) == 1
    end
  end

  describe "delete_schema/2 integrity guard" do
    defp insert_issued_credential(issuer, schema) do
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      {:ok, cred} =
        Sovra.Issuer.IssuedCredential.create_changeset(%{
          issuer_id: issuer.id,
          schema_id: schema.id,
          holder_did: "did:sovra:0xholder#{System.unique_integer([:positive])}",
          issued_at: now,
          expires_at: DateTime.add(now, 86400, :second)
        })
        |> Repo.insert()

      cred
    end

    test "rejects deletion when an issued credential references the schema" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)
      _cred = insert_issued_credential(issuer, schema)

      assert {:error, :schema_in_use} = Issuer.delete_schema(issuer.id, schema.id)
      assert {:ok, ^schema} = Issuer.get_schema_by_id(schema.id)
    end

    test "rejects deletion when a pending offer references the schema" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, _result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      assert {:error, :schema_in_use} = Issuer.delete_schema(issuer.id, schema.id)
    end

    test "rejects deletion when a token_exchanged offer references the schema" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, schema.schema_id, %{"name" => "Alice"})

      {:ok, _token_data} = Issuer.exchange_token(result.pre_authorized_code)

      assert {:error, :schema_in_use} = Issuer.delete_schema(issuer.id, schema.id)
    end

    test "deletes a schema with no issued credentials or open offers" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      assert {:ok, _} = Issuer.delete_schema(issuer.id, schema.id)
      assert {:error, :schema_not_found} = Issuer.get_schema_by_id(schema.id)
    end

    test "another workspace cannot delete a schema it does not own" do
      issuer_a = create_test_issuer()
      issuer_b = create_test_issuer()
      schema = create_test_schema(issuer_a)

      assert {:error, :schema_not_found} = Issuer.delete_schema(issuer_b.id, schema.id)
      assert {:ok, ^schema} = Issuer.get_schema_by_id(schema.id)
    end

    test "deleting any version cascades to all versions of the same schema_id" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      assert {:ok, %{deleted_versions: 2, schema_id: schema_id_str}} =
               Issuer.delete_schema(issuer.id, v2.id)

      assert schema_id_str == v1.schema_id
      assert {:error, :schema_not_found} = Issuer.get_schema_by_id(v1.id)
      assert {:error, :schema_not_found} = Issuer.get_schema_by_id(v2.id)
    end

    test "v2 cannot be deleted while v1 has issued credentials (atomic, all-or-nothing)" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)
      _cred = insert_issued_credential(issuer, v1)

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      assert {:error, :schema_in_use} = Issuer.delete_schema(issuer.id, v2.id)
      assert {:ok, _} = Issuer.get_schema_by_id(v1.id)
      assert {:ok, _} = Issuer.get_schema_by_id(v2.id)
    end

    test "v1 cannot be deleted while v2 has a pending offer (atomic, all-or-nothing)" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      {:ok, _result} =
        Issuer.create_credential_offer(issuer.id, v1.schema_id, %{"name" => "Bob"})

      assert {:error, :schema_in_use} = Issuer.delete_schema(issuer.id, v1.id)
      assert {:ok, _} = Issuer.get_schema_by_id(v1.id)
      assert {:ok, _} = Issuer.get_schema_by_id(v2.id)
    end

    test "cascade delete removes designs from all versions" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, _design_v1} =
        Issuer.upsert_design(issuer.id, v1.schema_id, %{
          name: "v1 design",
          display: %{title: %{text: "T"}},
          styles: %{
            thumbnail: %{uri: "https://example.com/x.png", alt: "x"},
            background: %{color: "#000000"},
            text: %{color: "#ffffff"}
          }
        })

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      assert {:ok, _} = Issuer.delete_schema(issuer.id, v2.id)

      assert Repo.get_by(Sovra.Issuer.CredentialDesign, credential_schema_id: v1.id) == nil
      assert Repo.get_by(Sovra.Issuer.CredentialDesign, credential_schema_id: v2.id) == nil
    end
  end

  describe "revise_schema/3 versioning" do
    test "inserts a new row with incremented version, preserves the prior row" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      assert schema.version == 1

      revised_claims = [
        %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true},
        %{"key" => "age", "type" => "integer", "required" => false, "disclosable" => true},
        %{"key" => "gpa", "type" => "number", "required" => false, "disclosable" => true}
      ]

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, schema.schema_id, 1, %{
          name: "Test Credential v2",
          claims: revised_claims,
          validity_period: "2y"
        })

      assert v2.version == 2
      assert v2.id != schema.id
      assert v2.schema_id == schema.schema_id
      assert v2.credential_type == schema.credential_type
      assert v2.name == "Test Credential v2"
      assert v2.validity_period == "2y"
      assert length(v2.claims) == 3

      # Prior row untouched
      {:ok, refetched_v1} = Issuer.get_schema_by_id(schema.id)
      assert refetched_v1.version == 1
      assert refetched_v1.name == "Test Credential"
      assert length(refetched_v1.claims) == 2
    end

    test "get_schema/2 returns the latest version after a revision" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, schema.schema_id, 1, %{
          name: "Test Credential v2",
          claims: schema.claims,
          validity_period: "1y"
        })

      {:ok, latest} = Issuer.get_schema(issuer.id, schema.schema_id)
      assert latest.id == v2.id
      assert latest.version == 2
    end

    test "credentials issued under v1 still resolve to v1 after a revision" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      now = DateTime.utc_now() |> DateTime.truncate(:second)

      {:ok, cred} =
        Sovra.Issuer.IssuedCredential.create_changeset(%{
          issuer_id: issuer.id,
          schema_id: v1.id,
          holder_did: "did:sovra:0xholder1",
          issued_at: now,
          expires_at: DateTime.add(now, 86400, :second)
        })
        |> Repo.insert()

      {:ok, _v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "Test Credential v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      reloaded = Repo.get!(Sovra.Issuer.IssuedCredential, cred.id)
      assert reloaded.schema_id == v1.id

      {:ok, resolved_schema} = Issuer.get_schema_by_id(reloaded.schema_id)
      assert resolved_schema.version == 1
    end

    test "new offers after revision target the latest version" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "Test Credential v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      {:ok, result} =
        Issuer.create_credential_offer(issuer.id, v1.schema_id, %{"name" => "Bob"})

      offer = Repo.get!(CredentialOffer, result.offer.id)
      assert offer.schema_id == v2.id
    end

    test "inherits the prior version's design" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, prior_design} =
        Issuer.upsert_design(issuer.id, v1.schema_id, %{
          name: "Diploma Card",
          description: "A test diploma",
          display: %{
            title: %{text: "Diploma"},
            subtitle: %{path: ["$.name"], fallback: "Unnamed"}
          },
          styles: %{
            thumbnail: %{uri: "https://example.com/logo.png", alt: "logo"},
            background: %{color: "#1a365d"},
            text: %{color: "#ffffff"}
          }
        })

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "Diploma v2",
          claims: v1.claims,
          validity_period: "2y"
        })

      {:ok, inherited} = Issuer.get_design(issuer.id, v1.schema_id)
      assert inherited.credential_schema_id == v2.id
      assert inherited.id != prior_design.id
      assert inherited.name == prior_design.name
      assert inherited.description == prior_design.description
      assert inherited.styles.background.color == "#1a365d"
      assert inherited.display.title.text == "Diploma"

      v1_design = Repo.get_by!(Sovra.Issuer.CredentialDesign, credential_schema_id: v1.id)
      assert v1_design.id == prior_design.id
    end

    test "revise without a prior design leaves the new version designless" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, _v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      assert {:error, :design_not_found} = Issuer.get_design(issuer.id, v1.schema_id)
    end

    test "returns :schema_not_found when revising a schema that does not exist" do
      issuer = create_test_issuer()

      assert {:error, :schema_not_found} =
               Issuer.revise_schema(issuer.id, "missing-schema", 1, %{
                 name: "Whatever",
                 claims: [],
                 validity_period: "1y"
               })
    end

    test "another workspace cannot revise a schema it does not own" do
      issuer_a = create_test_issuer()
      issuer_b = create_test_issuer()
      schema_a = create_test_schema(issuer_a)

      assert {:error, :schema_not_found} =
               Issuer.revise_schema(issuer_b.id, schema_a.schema_id, 1, %{
                 name: "Hijack",
                 claims: schema_a.claims,
                 validity_period: "1y"
               })

      {:ok, refetched} = Issuer.get_schema_by_id(schema_a.id)
      assert refetched.version == 1
      assert refetched.name == schema_a.name
    end

    test "inactive workspace cannot revise schemas" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      issuer
      |> Ecto.Changeset.change(%{status: "suspended"})
      |> Repo.update!()

      assert {:error, :workspace_inactive} =
               Issuer.revise_schema(issuer.id, schema.schema_id, 1, %{
                 name: "v2",
                 claims: schema.claims,
                 validity_period: "1y"
               })
    end

    test "inactive workspace cannot delete schemas" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      issuer
      |> Ecto.Changeset.change(%{status: "suspended"})
      |> Repo.update!()

      assert {:error, :workspace_inactive} = Issuer.delete_schema(issuer.id, schema.id)
    end

    test "stale base_version returns :schema_revision_conflict" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, _v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      # Second revise still thinks it's branching from v1 — the latest is now v2.
      assert {:error, :schema_revision_conflict} =
               Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
                 name: "v2-from-stale",
                 claims: v1.claims,
                 validity_period: "1y"
               })
    end

    test "matching base_version after a prior revision succeeds (chained revises)" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      assert v2.version == 2

      {:ok, v3} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 2, %{
          name: "v3",
          claims: v1.claims,
          validity_period: "1y"
        })

      assert v3.version == 3
    end
  end

  describe "OID4VCI.build_metadata projection — mdoc" do
    defp create_mdoc_schema(issuer) do
      attrs = %{
        schema_id: "mdoc-schema-#{System.unique_integer([:positive])}",
        credential_type: "MembershipCard",
        name: "Membership Card",
        format: "mso_mdoc",
        claims: [
          %{
            "key" => "member_name",
            "type" => "string",
            "required" => true,
            "disclosable" => true
          },
          %{"key" => "tier", "type" => "string", "required" => true, "disclosable" => false}
        ],
        validity_period: "1y"
      }

      {:ok, schema} = Issuer.create_schema(issuer.id, attrs)
      schema
    end

    test "emits an mso_mdoc configuration with the generated doctype" do
      issuer = create_test_issuer()
      schema = create_mdoc_schema(issuer)

      config =
        Sovra.Issuer.OID4VCI.build_metadata(issuer, [schema], [])
        |> get_in(["credential_configurations_supported", schema.credential_type])

      assert config["format"] == "mso_mdoc"
      assert config["doctype"] == Sovra.Mdoc.DocType.build(issuer, schema)
      assert config["cryptographic_binding_methods_supported"] == ["cose_key"]
      assert config["credential_signing_alg_values_supported"] == [-7]

      # The holder still proves possession with a plain OID4VCI jwt proof, so
      # no wallet-side change is needed to receive an mdoc.
      assert config["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"] ==
               ["ES256"]

      # An mdoc has no credential_definition — that is SD-JWT/W3C shaped.
      refute Map.has_key?(config, "credential_definition")
    end

    test "projects claims as [namespace, element] paths with mandatory flags" do
      issuer = create_test_issuer()
      schema = create_mdoc_schema(issuer)
      doc_type = Sovra.Mdoc.DocType.build(issuer, schema)

      config =
        Sovra.Issuer.OID4VCI.build_metadata(issuer, [schema], [])
        |> get_in(["credential_configurations_supported", schema.credential_type])

      # `disclosable: false` is what OID4VCI calls mandatory — the holder
      # cannot withhold it.
      assert config["credential_metadata"]["claims"] == [
               %{"path" => [doc_type, "member_name"], "mandatory" => false},
               %{"path" => [doc_type, "tier"], "mandatory" => true}
             ]
    end

    test "does not advertise the Sovra meta namespace" do
      # io.sovra.meta.1 rides inside an issued mdoc as plumbing. A wallet has
      # nothing to render for it and no reason to request it, so it must not
      # appear as a user-facing claim.
      issuer = create_test_issuer()
      schema = create_mdoc_schema(issuer)

      config =
        Sovra.Issuer.OID4VCI.build_metadata(issuer, [schema], [])
        |> get_in(["credential_configurations_supported", schema.credential_type])

      refute Enum.any?(config["credential_metadata"]["claims"], fn c ->
               c["path"] |> List.first() |> String.contains?("meta")
             end)
    end

    test "both formats coexist, each keyed by credential_type" do
      issuer = create_test_issuer()
      sd_jwt = create_test_schema(issuer)
      mdoc = create_mdoc_schema(issuer)

      configs =
        Sovra.Issuer.OID4VCI.build_metadata(issuer, [sd_jwt, mdoc], [])
        |> Map.fetch!("credential_configurations_supported")

      assert configs[sd_jwt.credential_type]["format"] == "vc+sd-jwt"
      assert configs[mdoc.credential_type]["format"] == "mso_mdoc"
    end

    test "reuses the shared display projection" do
      issuer = create_test_issuer()
      schema = create_mdoc_schema(issuer)

      config =
        Sovra.Issuer.OID4VCI.build_metadata(issuer, [schema], [])
        |> get_in(["credential_configurations_supported", schema.credential_type])

      assert config["credential_metadata"]["display"] == [%{"name" => schema.name}]
    end
  end

  describe "OID4VCI.build_metadata projection" do
    test "falls back to schema.name when no design exists" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      metadata = Sovra.Issuer.OID4VCI.build_metadata(issuer, [schema], [])

      config = metadata["credential_configurations_supported"][schema.credential_type]
      assert config["credential_metadata"]["display"] == [%{"name" => schema.name}]
    end

    test "projects design styling into OID4VCI display" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      {:ok, design} =
        Issuer.upsert_design(issuer.id, schema.schema_id, %{
          name: "Design Name",
          description: "A branded credential",
          display: %{title: %{text: "The Title"}},
          styles: %{
            thumbnail: %{uri: "data:image/png;base64,abc", alt: "seal"},
            background: %{color: "#1a365d"},
            text: %{color: "#ffffff"}
          }
        })

      metadata = Sovra.Issuer.OID4VCI.build_metadata(issuer, [schema], [design])

      [display_obj] =
        metadata["credential_configurations_supported"][schema.credential_type][
          "credential_metadata"
        ]["display"]

      assert display_obj["name"] == "The Title"
      assert display_obj["description"] == "A branded credential"
      assert display_obj["background_color"] == "#1a365d"
      assert display_obj["text_color"] == "#ffffff"
      assert display_obj["logo"]["uri"] == "data:image/png;base64,abc"
      assert display_obj["logo"]["alt_text"] == "seal"
    end

    test "advertises only the latest version per schema_id" do
      issuer = create_test_issuer()
      v1 = create_test_schema(issuer)

      {:ok, v2} =
        Issuer.revise_schema(issuer.id, v1.schema_id, 1, %{
          name: "Test Credential v2",
          claims: v1.claims,
          validity_period: "1y"
        })

      metadata = Sovra.Issuer.OID4VCI.build_metadata(issuer, [v1, v2], [])

      configs = metadata["credential_configurations_supported"]
      assert map_size(configs) == 1

      assert configs[v2.credential_type]["credential_metadata"]["display"] == [
               %{"name" => v2.name}
             ]
    end
  end
end
