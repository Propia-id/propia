defmodule Sovra.Issuer do
  @moduledoc """
  Credential issuance domain — credential schemas, offers, and delivery.

  Workspace lifecycle (creation, lookup, listing) lives in `Sovra.Workspaces`.
  This module only deals with the act of issuing credentials from a workspace.
  """

  alias Sovra.Issuer.{
    CredentialSchema,
    CredentialOffer,
    IssuedCredential,
    SDJWT,
    TokenHash,
    ClaimUtils
  }

  alias Sovra.Crypto.P256
  alias Sovra.Ethereum.{IssuerRegistry, RevocationRegistry}
  alias Sovra.Repo
  alias Sovra.Workspaces
  alias Sovra.Workspaces.Workspace

  import Ecto.Query

  require Logger

  @c_nonce_expires_in 86400

  # ── Schema Management ──────────────────────────────────

  def create_schema(workspace_id, attrs) do
    attrs = Map.put(attrs, :issuer_id, workspace_id)

    with {:ok, workspace} <- Workspaces.get_workspace(workspace_id),
         {:ok, schema} <- CredentialSchema.create_changeset(attrs) |> Repo.insert() do
      case register_credential_type_on_chain(workspace.eoa_address, schema.credential_type) do
        :ok ->
          :ok

        {:error, reason} ->
          Logger.warning("On-chain credential type registration failed: #{inspect(reason)}")
      end

      {:ok, schema}
    end
  end

  def get_schema(workspace_id, schema_id) do
    case Repo.get_by(CredentialSchema, issuer_id: workspace_id, schema_id: schema_id) do
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

  def list_schemas(workspace_id) do
    from(s in CredentialSchema,
      where: s.issuer_id == ^workspace_id,
      order_by: [asc: :inserted_at]
    )
    |> Repo.all()
  end

  def delete_schema(workspace_id, schema_id) do
    case Repo.get_by(CredentialSchema, id: schema_id, issuer_id: workspace_id) do
      nil -> {:error, :schema_not_found}
      schema -> Repo.delete(schema)
    end
  end

  # ── Offer & Credential Queries ──────────────────────────

  def list_offers(workspace_id) do
    from(o in CredentialOffer,
      where: o.issuer_id == ^workspace_id,
      order_by: [desc: :inserted_at],
      preload: [:schema]
    )
    |> Repo.all()
  end

  def list_issued_credentials(workspace_id) do
    from(c in IssuedCredential,
      where: c.issuer_id == ^workspace_id,
      order_by: [desc: :issued_at],
      preload: [:schema]
    )
    |> Repo.all()
  end

  # ── Credential Offer ───────────────────────────────────

  def create_credential_offer(workspace_id, schema_id, claims) do
    with {:ok, _workspace} <- Workspaces.get_workspace(workspace_id),
         {:ok, schema} <- get_schema(workspace_id, schema_id),
         :ok <- validate_claims(schema, claims),
         {:ok, status_list_index} <- assign_status_list_index(workspace_id) do
      {plaintext_code, code_hash} = TokenHash.generate_and_hash(32)

      expires_at =
        DateTime.utc_now() |> DateTime.add(86400, :second) |> DateTime.truncate(:second)

      changeset =
        CredentialOffer.create_changeset(%{
          issuer_id: workspace_id,
          schema_id: schema.id,
          pre_authorized_code_hash: code_hash,
          claims: claims,
          status_list_index: status_list_index,
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
        if DateTime.compare(DateTime.utc_now(), offer.expires_at) == :gt do
          {:error, :offer_expired}
        else
          case verify_proof(proof, offer.c_nonce) do
            {:ok, %{holder_did: holder_did}} ->
              deliver_credential(offer, holder_did)

            {:error, _} = error ->
              error
          end
        end

      _other ->
        {:error, :credential_already_issued}
    end
  end

  defp deliver_credential(offer, holder_did) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    with {:ok, workspace} <- Workspaces.get_workspace(offer.issuer_id),
         {:ok, schema} <- get_schema_by_id(offer.schema_id),
         {:ok, sd_jwt} <-
           SDJWT.build(workspace, schema, offer.claims, holder_did,
             status_list_index: offer.status_list_index
           ) do
      # Extract exp from the freshly-built SD-JWT
      [jwt_part | _] = String.split(sd_jwt, "~")
      [_, payload_b64 | _] = String.split(jwt_part, ".")
      {:ok, payload_json} = Base.url_decode64(payload_b64, padding: false)
      {:ok, payload} = Jason.decode(payload_json)
      {:ok, expires_at} = DateTime.from_unix(payload["exp"])
      expires_at = DateTime.truncate(expires_at, :second)

      issued_cred_changeset =
        IssuedCredential.create_changeset(%{
          issuer_id: offer.issuer_id,
          schema_id: offer.schema_id,
          holder_did: holder_did,
          status_list_index: offer.status_list_index,
          status_purpose: "revocation",
          issued_at: now,
          expires_at: expires_at
        })

      Repo.transaction(fn ->
        case Repo.insert(issued_cred_changeset) do
          {:ok, cred} ->
            case Repo.update(CredentialOffer.issued_changeset(offer)) do
              {:ok, _} ->
                {:ok, _} =
                  Sovra.Webhooks.enqueue(offer.issuer_id, "credential.issued", %{
                    "credential_id" => cred.id,
                    "holder_did" => cred.holder_did,
                    "schema_type" => schema.credential_type,
                    "issued_at" => DateTime.to_iso8601(cred.issued_at),
                    "expires_at" => DateTime.to_iso8601(cred.expires_at)
                  })

                sd_jwt

              {:error, reason} ->
                Repo.rollback(reason)
            end

          {:error, reason} ->
            Repo.rollback(reason)
        end
      end)
    end
  end

  # ── Proof Verification ─────────────────────────────────

  defp verify_proof(nil, _nonce), do: {:error, :invalid_proof}

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
         holder_did when is_binary(holder_did) <- payload["iss"],
         {:ok, {pub_x, pub_y}} <- extract_jwk_coordinates(header["jwk"]),
         {:ok, sig_bytes} <- Base.url_decode64(sig_b64, padding: false),
         <<r_bytes::binary-32, s_bytes::binary-32>> <- sig_bytes do
      signing_input = header_b64 <> "." <> payload_b64
      hash = :crypto.hash(:sha256, signing_input)

      if P256.verify(hash, %{r: r_bytes, s: s_bytes}, {pub_x, pub_y}) do
        {:ok, %{holder_did: holder_did}}
      else
        {:error, :invalid_proof}
      end
    else
      _ -> {:error, :invalid_proof}
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

  # ── Credential Status Management ─────────────────────

  def revoke_credential(workspace_id, credential_id) do
    change_credential_status(
      workspace_id,
      credential_id,
      "revoked",
      "credential.revoked",
      &RevocationRegistry.revoke/2
    )
  end

  def suspend_credential(workspace_id, credential_id) do
    change_credential_status(
      workspace_id,
      credential_id,
      "suspended",
      "credential.suspended",
      &RevocationRegistry.suspend/2
    )
  end

  def unsuspend_credential(workspace_id, credential_id) do
    change_credential_status(
      workspace_id,
      credential_id,
      "issued",
      "credential.unsuspended",
      &RevocationRegistry.unsuspend/2
    )
  end

  defp change_credential_status(workspace_id, credential_id, new_status, event, chain_call) do
    with {:ok, cred} <- get_issued_credential(workspace_id, credential_id),
         :ok <- validate_status_transition(cred, new_status),
         :ok <- maybe_sync_chain_status(chain_call, workspace_id, cred.status_list_index),
         {:ok, updated} <-
           cred |> IssuedCredential.status_changeset(new_status) |> Repo.update() do
      {:ok, schema} = get_schema_by_id(updated.schema_id)

      {:ok, _job} =
        Sovra.Webhooks.enqueue(workspace_id, event, %{
          "credential_id" => updated.id,
          "holder_did" => updated.holder_did,
          "schema_type" => schema.credential_type,
          "status_at" => DateTime.utc_now() |> DateTime.to_iso8601()
        })

      {:ok, updated}
    end
  end

  defp maybe_sync_chain_status(chain_call, workspace_id, index) do
    if ethereum_configured?() do
      case chain_call.(get_workspace_eoa(workspace_id), index) do
        {:ok, _tx} -> :ok
        {:error, _} = error -> error
      end
    else
      :ok
    end
  end

  defp get_issued_credential(workspace_id, id) do
    case Repo.get_by(IssuedCredential, id: id, issuer_id: workspace_id) do
      nil -> {:error, :credential_not_found}
      cred -> {:ok, cred}
    end
  end

  defp validate_status_transition(%{status: "issued"}, "revoked"), do: :ok
  defp validate_status_transition(%{status: "issued"}, "suspended"), do: :ok
  defp validate_status_transition(%{status: "suspended"}, "revoked"), do: :ok
  defp validate_status_transition(%{status: "suspended"}, "issued"), do: :ok
  defp validate_status_transition(_cred, _target), do: {:error, :invalid_status_transition}

  defp get_workspace_eoa(workspace_id) do
    Repo.get!(Workspace, workspace_id).eoa_address
  end

  # ── Status List Index Assignment ─────────────────────

  @max_status_list_index 131_071

  defp assign_status_list_index(issuer_id, purpose \\ "revocation") do
    used_indices =
      from(c in IssuedCredential,
        where: c.issuer_id == ^issuer_id and c.status_purpose == ^purpose,
        select: c.status_list_index
      )
      |> Repo.all()
      |> Enum.reject(&is_nil/1)
      |> MapSet.new()

    # Also reserve indices from pending offers
    offer_indices =
      from(o in CredentialOffer,
        where: o.issuer_id == ^issuer_id and not is_nil(o.status_list_index),
        select: o.status_list_index
      )
      |> Repo.all()
      |> MapSet.new()

    all_used = MapSet.union(used_indices, offer_indices)
    available_count = @max_status_list_index + 1 - MapSet.size(all_used)

    if available_count <= 0 do
      {:error, :bitmap_exhausted}
    else
      {:ok, find_random_unused_index(all_used)}
    end
  end

  defp find_random_unused_index(used) do
    candidate = :rand.uniform(@max_status_list_index + 1) - 1

    if MapSet.member?(used, candidate) do
      find_random_unused_index(used)
    else
      candidate
    end
  end

  # ── On-Chain Registration Helpers ─────────────────────

  defp initialize_bitmaps_on_chain(eoa_address) do
    if ethereum_configured?() do
      with {:ok, _} <- RevocationRegistry.initialize_bitmap(eoa_address, 0),
           {:ok, _} <- RevocationRegistry.initialize_bitmap(eoa_address, 1) do
        :ok
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
          with {:ok, _tx_hash} <- IssuerRegistry.register_issuer(eoa_address, [type_hash]),
               :ok <- initialize_bitmaps_on_chain(eoa_address) do
            :ok
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
