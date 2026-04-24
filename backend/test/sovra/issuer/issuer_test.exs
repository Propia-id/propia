defmodule Sovra.IssuerTest do
  use Sovra.DataCase, async: false

  alias Sovra.Issuer
  alias Sovra.Issuer.{CredentialOffer, TokenHash}
  alias Sovra.Crypto.P256
  alias Sovra.Organizations.Organization
  alias Sovra.Workspaces

  setup do
    # Ensure SoftwareKeyStore is running
    :ok
  end

  defp create_test_issuer do
    {:ok, org} =
      %{name: "Test Org"}
      |> Organization.create_changeset()
      |> Repo.insert()

    {:ok, workspace} = Workspaces.create_workspace("Test Issuer", org.id)
    workspace
  end

  defp create_test_schema(issuer) do
    attrs = %{
      schema_id: "test-schema-#{System.unique_integer([:positive])}",
      credential_type: "TestCredential",
      name: "Test Credential",
      claims: [
        %{"key" => "name", "type" => "string", "required" => true, "disclosable" => true},
        %{"key" => "age", "type" => "integer", "required" => false, "disclosable" => true}
      ],
      validity_period: "1y"
    }

    {:ok, schema} = Issuer.create_schema(issuer.id, attrs)
    schema
  end

  describe "Workspaces.create_workspace/2" do
    test "creates workspace with proper EOA address derived from secp256k1 keypair" do
      {:ok, org} =
        %{name: "Org #{System.unique_integer([:positive])}"}
        |> Organization.create_changeset()
        |> Repo.insert()

      {:ok, issuer} = Workspaces.create_workspace("New Issuer", org.id)
      assert issuer.name == "New Issuer"
      assert String.starts_with?(issuer.eoa_address, "0x")
      assert String.length(issuer.eoa_address) == 42
      assert String.starts_with?(issuer.did, "did:sovra:0x")
      assert issuer.status == "active"
      refute String.starts_with?(issuer.eoa_key_id, "stub_")
      assert issuer.organization_id == org.id
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

  describe "issue_credential/2 with proof verification" do
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

      proof = %{"jwt" => jwt}
      assert {:error, :invalid_proof} = Issuer.issue_credential(token_data.access_token, proof)
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

      proof = %{"jwt" => jwt}
      assert {:ok, sd_jwt} = Issuer.issue_credential(token_data.access_token, proof)
      assert is_binary(sd_jwt)
      assert String.contains?(sd_jwt, "~")

      # Verify the SD-JWT has the correct holder DID as sub
      [jwt_part | _] = String.split(sd_jwt, "~")
      [_, payload_b64 | _] = String.split(jwt_part, ".")
      {:ok, payload_json} = Base.url_decode64(payload_b64, padding: false)
      {:ok, jwt_payload} = Jason.decode(payload_json)
      assert jwt_payload["sub"] == holder_did
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

      proof = %{"jwt" => jwt}
      assert {:error, :invalid_proof} = Issuer.issue_credential(token_data.access_token, proof)
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

      proof = %{"jwt" => jwt}
      assert {:error, :invalid_proof} = Issuer.issue_credential(token_data.access_token, proof)
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

      {:ok, _sd_jwt} = Issuer.issue_credential(token_data.access_token, %{"jwt" => jwt})

      # Verify sensitive data is cleared
      offer = Repo.get!(CredentialOffer, offer_result.offer.id)
      assert offer.status == "issued"
      assert is_nil(offer.claims)
      assert is_nil(offer.pre_authorized_code_hash)
      assert is_nil(offer.access_token_hash)
    end
  end
end
