defmodule SovraWeb.Issuer.CredentialController do
  use SovraWeb, :controller

  alias Sovra.Issuer

  def offer(conn, params) do
    issuer_id = params["issuer_id"]
    schema_id = params["schema_id"]
    holder_did = params["holder_did"]
    claims = params["claims"]

    case Issuer.create_credential_offer(issuer_id, schema_id, holder_did, claims) do
      {:ok, %{offer: offer, offer_uri: offer_uri}} ->
        conn
        |> put_status(201)
        |> json(%{
          offer_id: offer.id,
          offer_uri: offer_uri,
          pre_authorized_code: offer.pre_authorized_code,
          expires_at: DateTime.to_iso8601(offer.expires_at)
        })

      {:error, :issuer_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})

      {:error, :schema_not_found} ->
        conn |> put_status(404) |> json(%{error: "schema_not_found"})

      {:error, {:missing_claims, missing}} ->
        conn |> put_status(422) |> json(%{error: "missing_claims", missing: missing})

      {:error, reason} ->
        conn |> put_status(500) |> json(%{error: inspect(reason)})
    end
  end

  def authorize(conn, _params) do
    conn |> put_status(404) |> json(%{error: "not_supported"})
  end

  def token(conn, params) do
    grant_type = params["grant_type"]
    code = params["pre-authorized_code"]
    tx_code = params["tx_code"]

    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code" do
      conn |> put_status(400) |> json(%{error: "unsupported_grant_type"})
    else
      case Issuer.exchange_token(code, tx_code) do
        {:ok, %{access_token: token, c_nonce: nonce, expires_in: expires_in}} ->
          json(conn, %{
            access_token: token,
            c_nonce: nonce,
            token_type: "bearer",
            expires_in: expires_in
          })

        {:error, :invalid_code} ->
          conn |> put_status(400) |> json(%{error: "invalid_grant"})

        {:error, :offer_expired} ->
          conn |> put_status(400) |> json(%{error: "expired_grant"})

        {:error, :invalid_tx_code} ->
          conn |> put_status(400) |> json(%{error: "invalid_tx_code"})

        {:error, :code_already_used} ->
          conn |> put_status(400) |> json(%{error: "invalid_grant"})

        {:error, reason} ->
          conn |> put_status(500) |> json(%{error: inspect(reason)})
      end
    end
  end

  def issue(conn, params) do
    access_token = extract_bearer_token(conn)
    proof = params["proof"]

    if is_nil(access_token) do
      conn |> put_status(401) |> json(%{error: "missing_token"})
    else
      case Issuer.issue_credential(access_token, proof) do
        {:ok, sd_jwt} ->
          json(conn, %{credential: sd_jwt, format: "vc+sd-jwt"})

        {:error, :invalid_token} ->
          conn |> put_status(401) |> json(%{error: "invalid_token"})

        {:error, :offer_expired} ->
          conn |> put_status(400) |> json(%{error: "expired_token"})

        {:error, :invalid_proof} ->
          conn |> put_status(400) |> json(%{error: "invalid_proof"})

        {:error, :credential_already_issued} ->
          conn |> put_status(400) |> json(%{error: "credential_already_issued"})

        {:error, reason} ->
          conn |> put_status(500) |> json(%{error: inspect(reason)})
      end
    end
  end

  defp extract_bearer_token(conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> token
      _ -> nil
    end
  end
end
