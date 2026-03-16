defmodule Sovra.Issuer do
  @moduledoc """
  Credential issuance domain — manages credential types, issuance flows, and issuer state.
  """

  alias Sovra.Issuer.{IssuerRecord, CredentialSchema, CredentialOffer, IssuedCredential, SDJWT}
  alias Sovra.Crypto.Key
  alias Sovra.Ethereum.{DIDRegistry, IssuerRegistry}
  alias Sovra.Repo

  import Ecto.Query

  require Logger

  # ── Issuer Management ──────────────────────────────────

  def create_issuer(name) do
    issuer_uuid = Ecto.UUID.generate()

    with {:ok, %{key_id: key_id, public_key_x: x, public_key_y: y}} <-
           Key.generate_key("issuer_#{issuer_uuid}_signing") do
      eoa_address = "0x" <> Base.encode16(:crypto.strong_rand_bytes(20), case: :lower)

      # Register DID on-chain if Ethereum is configured
      case register_did_on_chain(eoa_address, x, y) do
        :ok ->
          :ok

        {:error, reason} ->
          Logger.warning("On-chain DID registration skipped: #{inspect(reason)}")
      end

      changeset =
        IssuerRecord.create_changeset(%{
          name: name,
          eoa_address: eoa_address,
          eoa_key_id: "stub_#{issuer_uuid}",
          signing_key_id: key_id,
          signing_public_key_x: x,
          signing_public_key_y: y,
          did: "did:sovra:#{eoa_address}"
        })

      Repo.insert(changeset)
    end
  end

  def get_issuer(id) do
    case Repo.get(IssuerRecord, id) do
      nil -> {:error, :issuer_not_found}
      issuer -> {:ok, issuer}
    end
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
      # Register issuer for this credential type on-chain
      register_credential_type_on_chain(issuer.eoa_address, schema.credential_type)
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
      pre_authorized_code = random_hex(32)

      expires_at =
        DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)

      changeset =
        CredentialOffer.create_changeset(%{
          issuer_id: issuer_id,
          schema_id: schema.id,
          holder_did: holder_did,
          pre_authorized_code: pre_authorized_code,
          claims: claims,
          sd_jwt: sd_jwt,
          expires_at: expires_at
        })

      case Repo.insert(changeset) do
        {:ok, offer} ->
          base_url = base_url()
          offer_uri = build_offer_uri(offer, issuer, schema, base_url)
          {:ok, %{offer: offer, offer_uri: offer_uri}}

        {:error, _} = error ->
          error
      end
    end
  end

  def build_offer_uri(offer, _issuer, schema, base_url) do
    offer_json =
      Jason.encode!(%{
        "credential_issuer" => base_url,
        "credential_configuration_ids" => [schema.credential_type],
        "grants" => %{
          "urn:ietf:params:oauth:grant-type:pre-authorized_code" =>
            Map.merge(
              %{"pre-authorized_code" => offer.pre_authorized_code},
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
    case Repo.get_by(CredentialOffer, pre_authorized_code: pre_authorized_code) do
      nil ->
        {:error, :invalid_code}

      %{status: "pending"} = offer ->
        cond do
          DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt ->
            {:error, :offer_expired}

          offer.tx_code != nil and offer.tx_code != tx_code ->
            {:error, :invalid_tx_code}

          true ->
            access_token = random_hex(32)
            c_nonce = random_hex(16)

            changeset =
              CredentialOffer.token_exchanged_changeset(offer, %{
                access_token: access_token,
                c_nonce: c_nonce
              })

            case Repo.update(changeset) do
              {:ok, _} ->
                {:ok, %{access_token: access_token, c_nonce: c_nonce, expires_in: 86400}}

              {:error, _} = error ->
                error
            end
        end

      _other ->
        {:error, :code_already_used}
    end
  end

  # ── Credential Delivery ────────────────────────────────

  def issue_credential(access_token, proof) do
    case Repo.get_by(CredentialOffer, access_token: access_token) do
      nil ->
        {:error, :invalid_token}

      %{status: "token_exchanged"} = offer ->
        cond do
          DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt ->
            {:error, :offer_expired}

          not valid_proof_structure?(proof, offer.c_nonce) ->
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

    # Decode the SD-JWT to get expiry from the payload
    [jwt_part | _] = String.split(offer.sd_jwt, "~")
    [_, payload_b64 | _] = String.split(jwt_part, ".")
    {:ok, payload_json} = Base.url_decode64(payload_b64, padding: false)
    payload = Jason.decode!(payload_json)
    exp = payload["exp"]
    expires_at = DateTime.from_unix!(exp) |> DateTime.truncate(:second)

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
            {:ok, _} -> offer.sd_jwt
            {:error, reason} -> Repo.rollback(reason)
          end

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  # ── Validation Helpers ─────────────────────────────────

  defp validate_claims(schema, claims) do
    claim_defs = parse_claim_defs(schema.claims)
    required_keys = claim_defs |> Enum.filter(& &1["required"]) |> Enum.map(& &1["key"])
    missing = Enum.reject(required_keys, &Map.has_key?(claims, &1))

    if missing == [] do
      :ok
    else
      {:error, {:missing_claims, missing}}
    end
  end

  defp parse_claim_defs(claims) when is_list(claims), do: claims

  defp parse_claim_defs(claims) when is_map(claims) do
    case Map.get(claims, "claims") do
      list when is_list(list) -> list
      _ -> []
    end
  end

  defp valid_proof_structure?(nil, _nonce), do: false

  defp valid_proof_structure?(proof, nonce) do
    with jwt when is_binary(jwt) <- Map.get(proof, "jwt") || Map.get(proof, :jwt),
         [header_b64, payload_b64 | _] <- String.split(jwt, "."),
         {:ok, header_json} <- Base.url_decode64(header_b64, padding: false),
         {:ok, payload_json} <- Base.url_decode64(payload_b64, padding: false),
         {:ok, header} <- Jason.decode(header_json),
         {:ok, payload} <- Jason.decode(payload_json) do
      header["typ"] == "openid4vci-proof+jwt" and
        header["alg"] == "ES256" and
        payload["nonce"] == nonce
    else
      _ -> false
    end
  end

  defp random_hex(bytes) do
    :crypto.strong_rand_bytes(bytes) |> Base.encode16(case: :lower)
  end

  defp base_url do
    Application.get_env(:sovra, :issuer, []) |> Keyword.get(:base_url, "http://localhost:4000")
  end

  # ── On-Chain Registration Helpers ─────────────────────

  defp register_did_on_chain(eoa_address, pub_key_x, pub_key_y) do
    if ethereum_configured?() do
      service_endpoint = base_url()

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
            {:ok, _tx_hash} ->
              :ok

            {:error, reason} ->
              Logger.warning("Failed to add credential type on-chain: #{inspect(reason)}")
          end

        {:ok, false} ->
          case IssuerRegistry.register_issuer(eoa_address, [type_hash]) do
            {:ok, _tx_hash} ->
              :ok

            {:error, reason} ->
              Logger.warning("Failed to register issuer on-chain: #{inspect(reason)}")
          end

        {:error, reason} ->
          Logger.warning("Failed to check issuer registration: #{inspect(reason)}")
      end
    end
  end

  defp ethereum_configured? do
    config = Application.get_env(:sovra, :ethereum, [])
    config[:admin_private_key] != nil and config[:did_registry_address] != nil
  end
end
