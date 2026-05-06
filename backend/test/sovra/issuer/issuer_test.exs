defmodule Sovra.IssuerTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Accounts.User
  alias Sovra.Issuer
  alias Sovra.Issuer.{CredentialOffer, TokenHash}
  alias Sovra.Crypto.P256
  alias Sovra.Organizations.Organization
  alias Sovra.Webhooks.DeliveryJob
  alias Sovra.Workspaces

  setup do
    # Ensure SoftwareKeyStore is running
    :ok
  end

  defp create_test_user do
    {:ok, account} =
      User.admin_changeset(%{
        email: "owner-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    account
  end

  defp create_test_issuer do
    {:ok, org} =
      %{name: "Test Org"}
      |> Organization.create_changeset()
      |> Repo.insert()

    user = create_test_user()

    {:ok, %{workspace: workspace}} =
      Workspaces.create_workspace(org.id, %{name: "Test Issuer"}, user.id)

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

  describe "Workspaces.create_workspace/3" do
    test "creates workspace with proper EOA address derived from secp256k1 keypair" do
      user = create_test_user()

      {:ok, org} =
        %{name: "Org #{System.unique_integer([:positive])}"}
        |> Organization.create_changeset()
        |> Repo.insert()

      {:ok, %{workspace: issuer, webhook_secret: webhook_secret}} =
        Workspaces.create_workspace(org.id, %{name: "New Issuer"}, user.id)

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

      assert {:ok, sd_jwt} =
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

  describe "OID4VCI.build_metadata projection" do
    test "falls back to schema.name when no design exists" do
      issuer = create_test_issuer()
      schema = create_test_schema(issuer)

      metadata = Sovra.Issuer.OID4VCI.build_metadata(issuer, [schema], [])

      config = metadata["credential_configurations_supported"][schema.credential_type]
      assert config["display"] == [%{"name" => schema.name}]
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
        metadata["credential_configurations_supported"][schema.credential_type]["display"]

      assert display_obj["name"] == "The Title"
      assert display_obj["description"] == "A branded credential"
      assert display_obj["background_color"] == "#1a365d"
      assert display_obj["text_color"] == "#ffffff"
      assert display_obj["logo"]["uri"] == "data:image/png;base64,abc"
      assert display_obj["logo"]["alt_text"] == "seal"
    end
  end
end
