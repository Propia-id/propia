defmodule Sovra.Issuer do
  @moduledoc """
  Credential issuance domain — manages credential types, issuance flows, and issuer state.
  """

  alias Sovra.Issuer.{
    IssuerRecord,
    CredentialSchema,
    CredentialOffer,
    IssuedCredential,
    SDJWT,
    TokenHash,
    ClaimUtils
  }

  alias Sovra.Crypto.{Key, P256}
  alias Sovra.Ethereum.{DIDRegistry, IssuerRegistry}
  alias Sovra.Repo

  import Ecto.Query

  require Logger

  @c_nonce_expires_in 86400

  # ── Issuer Management ──────────────────────────────────

  def create_issuer(name) do
    issuer_uuid = Ecto.UUID.generate()

    with {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} <-
           Key.generate_key("issuer_#{issuer_uuid}_signing"),
         {:ok, eoa_address, eoa_key_id} <- generate_eoa_keypair(issuer_uuid) do
      changeset =
        IssuerRecord.create_changeset(%{
          name: name,
          eoa_address: eoa_address,
          eoa_key_id: eoa_key_id,
          signing_key_id: key_id,
          signing_public_key_x: x,
          signing_public_key_y: y,
          did: "did:sovra:#{eoa_address}"
        })

      Ecto.Multi.new()
      |> Ecto.Multi.insert(:issuer, changeset)
      |> Ecto.Multi.run(:register_did, fn _repo, %{issuer: issuer} ->
        case register_did_on_chain(issuer.eoa_address, x, y) do
          :ok -> {:ok, :registered}
          {:error, :ethereum_not_configured} -> {:ok, :skipped}
          {:error, reason} -> {:error, reason}
        end
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{issuer: issuer}} -> {:ok, issuer}
        {:error, :register_did, reason, _} -> {:error, {:chain_registration_failed, reason}}
        {:error, :issuer, changeset, _} -> {:error, changeset}
      end
    end
  end

  defp generate_eoa_keypair(issuer_uuid) do
    private_key = :crypto.strong_rand_bytes(32)

    case ExSecp256k1.create_public_key(private_key) do
      {:ok, public_key} ->
        <<4, pub_bytes::binary-64>> = public_key
        address_bytes = ExKeccak.hash_256(pub_bytes) |> binary_part(12, 20)
        eoa_address = "0x" <> Base.encode16(address_bytes, case: :lower)

        eoa_key_id = "issuer_#{issuer_uuid}_eoa"

        {:ok, eoa_address, eoa_key_id}

      {:error, _} = error ->
        error
    end
  end

  def get_issuer(id) do
    case Repo.get(IssuerRecord, id) do
      nil -> {:error, :issuer_not_found}
      issuer -> {:ok, issuer}
    end
  end

  def list_issuers do
    from(i in IssuerRecord,
      left_join: a in Sovra.Issuer.IssuerAccount,
      on: a.issuer_id == i.id,
      order_by: [desc: i.inserted_at],
      select: %{id: i.id, name: i.name, did: i.did, status: i.status, email: a.email}
    )
    |> Repo.all()
  end

  def get_first_issuer do
    case Repo.one(from(i in IssuerRecord, where: i.status == "active", limit: 1)) do
      nil -> {:error, :no_issuers}
      issuer -> {:ok, issuer}
    end
  end

  # ── Schema Management ──────────────────────────────────

  def create_schema(issuer_id, attrs) do
    attrs = Map.put(attrs, :issuer_id, issuer_id)

    with {:ok, issuer} <- get_issuer(issuer_id),
         {:ok, schema} <- CredentialSchema.create_changeset(attrs) |> Repo.insert() do
      case register_credential_type_on_chain(issuer.eoa_address, schema.credential_type) do
        :ok ->
          :ok

        {:error, reason} ->
          Logger.warning("On-chain credential type registration failed: #{inspect(reason)}")
      end

      {:ok, schema}
    end
  end

  def get_schema(issuer_id, schema_id) do
    case Repo.get_by(CredentialSchema, issuer_id: issuer_id, schema_id: schema_id) do
      nil -> {:error, :schema_not_found}
      schema -> {:ok, schema}
    end
  end

  def get_schema_by_id(id) do
    case Repo.get(CredentialSchema, id) do
      nil -> {:error, :schema_not_found}
      schema -> {:ok, schema}
    end
  end

  def list_schemas(issuer_id) do
    from(s in CredentialSchema, where: s.issuer_id == ^issuer_id, order_by: [asc: :inserted_at])
    |> Repo.all()
  end

  def delete_schema(issuer_id, schema_id) do
    case Repo.get_by(CredentialSchema, id: schema_id, issuer_id: issuer_id) do
      nil -> {:error, :schema_not_found}
      schema -> Repo.delete(schema)
    end
  end

  # ── Offer & Credential Queries ──────────────────────────

  def list_offers(issuer_id) do
    from(o in CredentialOffer,
      where: o.issuer_id == ^issuer_id,
      order_by: [desc: :inserted_at],
      preload: [:schema]
    )
    |> Repo.all()
  end

  def list_issued_credentials(issuer_id) do
    from(c in IssuedCredential,
      where: c.issuer_id == ^issuer_id,
      order_by: [desc: :issued_at],
      preload: [:schema]
    )
    |> Repo.all()
  end

  # ── Credential Offer ───────────────────────────────────

  def create_credential_offer(issuer_id, schema_id, holder_did, claims) do
    with {:ok, issuer} <- get_issuer(issuer_id),
         {:ok, schema} <- get_schema(issuer_id, schema_id),
         :ok <- validate_claims(schema, claims),
         {:ok, sd_jwt} <- SDJWT.build(issuer, schema, claims, holder_did) do
      {plaintext_code, code_hash} = TokenHash.generate_and_hash(32)

      expires_at =
        DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)

      changeset =
        CredentialOffer.create_changeset(%{
          issuer_id: issuer_id,
          schema_id: schema.id,
          holder_did: holder_did,
          pre_authorized_code_hash: code_hash,
          claims: claims,
          sd_jwt: sd_jwt,
          expires_at: expires_at
        })

      case Repo.insert(changeset) do
        {:ok, offer} ->
          base_url = ClaimUtils.base_url()
          offer_uri = build_offer_uri(plaintext_code, offer, schema, base_url)
          {:ok, %{offer: offer, offer_uri: offer_uri, pre_authorized_code: plaintext_code}}

        {:error, _} = error ->
          error
      end
    end
  end

  def build_offer_uri(pre_authorized_code, offer, schema, base_url) do
    offer_json =
      Jason.encode!(%{
        "credential_issuer" => base_url,
        "credential_configuration_ids" => [schema.credential_type],
        "grants" => %{
          "urn:ietf:params:oauth:grant-type:pre-authorized_code" =>
            Map.merge(
              %{"pre-authorized_code" => pre_authorized_code},
              if(offer.tx_code,
                do: %{"tx_code" => %{"input_mode" => "numeric", "length" => 6}},
                else: %{}
              )
            )
        }
      })

    "openid-credential-offer://?credential_offer=#{URI.encode(offer_json)}"
  end

  # ── Token Exchange ─────────────────────────────────────

  def exchange_token(pre_authorized_code, tx_code \\ nil) do
    code_hash = TokenHash.hash(pre_authorized_code)

    case Repo.get_by(CredentialOffer, pre_authorized_code_hash: code_hash) do
      nil ->
        {:error, :invalid_code}

      %{status: "pending"} = offer ->
        cond do
          DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt ->
            {:error, :offer_expired}

          offer.tx_code != nil and offer.tx_code != tx_code ->
            check_tx_code_lockout(offer)

          true ->
            {plaintext_token, token_hash} = TokenHash.generate_and_hash(32)
            c_nonce = random_hex(16)

            changeset =
              CredentialOffer.token_exchanged_changeset(offer, %{
                access_token_hash: token_hash,
                c_nonce: c_nonce
              })

            case Repo.update(changeset) do
              {:ok, _} ->
                {:ok,
                 %{
                   access_token: plaintext_token,
                   c_nonce: c_nonce,
                   c_nonce_expires_in: @c_nonce_expires_in,
                   expires_in: 86400
                 }}

              {:error, _} = error ->
                error
            end
        end

      _other ->
        {:error, :code_already_used}
    end
  end

  defp check_tx_code_lockout(offer) do
    bucket = "tx_code:#{offer.id}"

    case Hammer.check_rate(bucket, 300_000, 5) do
      {:allow, _count} ->
        {:error, :invalid_tx_code}

      {:deny, _limit} ->
        {:error, :offer_locked}
    end
  end

  # ── Credential Delivery ────────────────────────────────

  def issue_credential(access_token, proof) do
    token_hash = TokenHash.hash(access_token)

    case Repo.get_by(CredentialOffer, access_token_hash: token_hash) do
      nil ->
        {:error, :invalid_token}

      %{status: "token_exchanged"} = offer ->
        cond do
          DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt ->
            {:error, :offer_expired}

          not verify_proof(proof, offer.c_nonce) ->
            {:error, :invalid_proof}

          true ->
            deliver_credential(offer)
        end

      _other ->
        {:error, :credential_already_issued}
    end
  end

  defp deliver_credential(offer) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    with [jwt_part | _] <- String.split(offer.sd_jwt, "~"),
         [_, payload_b64 | _] <- String.split(jwt_part, "."),
         {:ok, payload_json} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, payload} <- Jason.decode(payload_json),
         exp when is_integer(exp) <- Map.get(payload, "exp"),
         {:ok, expires_at} <- DateTime.from_unix(exp) do
      expires_at = DateTime.truncate(expires_at, :second)
      sd_jwt = offer.sd_jwt

      issued_cred_changeset =
        IssuedCredential.create_changeset(%{
          issuer_id: offer.issuer_id,
          schema_id: offer.schema_id,
          holder_did: offer.holder_did,
          issued_at: now,
          expires_at: expires_at
        })

      Repo.transaction(fn ->
        case Repo.insert(issued_cred_changeset) do
          {:ok, _cred} ->
            case Repo.update(CredentialOffer.issued_changeset(offer)) do
              {:ok, _} -> sd_jwt
              {:error, reason} -> Repo.rollback(reason)
            end

          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    else
      _ -> {:error, :invalid_credential_data}
    end
  end

  # ── Proof Verification ─────────────────────────────────

  defp verify_proof(nil, _nonce), do: false

  defp verify_proof(proof, nonce) do
    with jwt when is_binary(jwt) <- Map.get(proof, "jwt") || Map.get(proof, :jwt),
         [header_b64, payload_b64, sig_b64] <- String.split(jwt, "."),
         {:ok, header_json} <- Base.url_decode64(header_b64, padding: false),
         {:ok, payload_json} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, header} <- Jason.decode(header_json),
         {:ok, payload} <- Jason.decode(payload_json),
         true <- header["typ"] == "openid4vci-proof+jwt",
         true <- header["alg"] == "ES256",
         true <- payload["nonce"] == nonce,
         {:ok, {pub_x, pub_y}} <- extract_jwk_coordinates(header["jwk"]),
         {:ok, sig_bytes} <- Base.url_decode64(sig_b64, padding: false),
         <<r_bytes::binary-32, s_bytes::binary-32>> <- sig_bytes do
      signing_input = header_b64 <> "." <> payload_b64
      hash = :crypto.hash(:sha256, signing_input)
      P256.verify(hash, %{r: r_bytes, s: s_bytes}, {pub_x, pub_y})
    else
      _ -> false
    end
  end

  defp extract_jwk_coordinates(%{"x" => x_b64, "y" => y_b64}) do
    with {:ok, x} <- Base.url_decode64(x_b64, padding: false),
         {:ok, y} <- Base.url_decode64(y_b64, padding: false),
         true <- byte_size(x) == 32 and byte_size(y) == 32 do
      {:ok, {x, y}}
    else
      _ -> :error
    end
  end

  defp extract_jwk_coordinates(_), do: :error

  # ── Validation Helpers ─────────────────────────────────

  defp validate_claims(schema, claims) do
    claim_defs = ClaimUtils.parse_claim_defs(schema.claims)
    required_keys = claim_defs |> Enum.filter(& &1["required"]) |> Enum.map(& &1["key"])
    missing = Enum.reject(required_keys, &Map.has_key?(claims, &1))

    if missing == [] do
      :ok
    else
      {:error, {:missing_claims, missing}}
    end
  end

  defp random_hex(bytes) do
    :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)
  end

  # ── On-Chain Registration Helpers ─────────────────────

  defp register_did_on_chain(eoa_address, pub_key_x, pub_key_y) do
    if ethereum_configured?() do
      service_endpoint = ClaimUtils.base_url()

      case DIDRegistry.register_issuer_did(eoa_address, pub_key_x, pub_key_y, service_endpoint) do
        {:ok, _tx_hash} -> :ok
        {:error, _} = error -> error
      end
    else
      {:error, :ethereum_not_configured}
    end
  end

  defp register_credential_type_on_chain(eoa_address, credential_type) do
    if ethereum_configured?() do
      type_hash = IssuerRegistry.credential_type_hash(credential_type)

      case IssuerRegistry.is_registered(eoa_address) do
        {:ok, true} ->
          case IssuerRegistry.add_credential_types(eoa_address, [type_hash]) do
            {:ok, _tx_hash} -> :ok
            {:error, reason} -> {:error, reason}
          end

        {:ok, false} ->
          case IssuerRegistry.register_issuer(eoa_address, [type_hash]) do
            {:ok, _tx_hash} -> :ok
            {:error, reason} -> {:error, reason}
          end

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :ethereum_not_configured}
    end
  end

  defp ethereum_configured? do
    config = Application.get_env(:sovra, :ethereum, [])
    config[:admin_private_key] != nil and config[:did_registry_address] != nil
  end
end
