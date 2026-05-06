defmodule SovraWeb.Issuer.CredentialController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Issuer

  tags(["Issuer OID4VCI"])

  operation(:authorize,
    summary: "Authorization (not supported)",
    description: "This endpoint is not supported in the current OID4VCI flow.",
    responses: %{
      404 =>
        {"Not supported", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string, example: "not_supported"}}
         }}
    }
  )

  operation(:token,
    summary: "Exchange pre-authorized code for access token",
    description: "OID4VCI token endpoint. Rate limited to 10 requests per minute.",
    request_body:
      {"Token request", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:grant_type, :"pre-authorized_code"],
         properties: %{
           grant_type: %OpenApiSpex.Schema{
             type: :string,
             example: "urn:ietf:params:oauth:grant-type:pre-authorized_code"
           },
           "pre-authorized_code": %OpenApiSpex.Schema{type: :string},
           tx_code: %OpenApiSpex.Schema{type: :string}
         }
       }},
    responses: %{
      200 =>
        {"Token response", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             access_token: %OpenApiSpex.Schema{type: :string},
             c_nonce: %OpenApiSpex.Schema{type: :string},
             c_nonce_expires_in: %OpenApiSpex.Schema{type: :integer},
             token_type: %OpenApiSpex.Schema{type: :string, example: "bearer"},
             expires_in: %OpenApiSpex.Schema{type: :integer}
           }
         }},
      400 =>
        {"Bad request", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      429 =>
        {"Too many attempts", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string, example: "too_many_attempts"}}
         }}
    }
  )

  operation(:issue,
    summary: "Issue credential",
    description:
      "Issue a verifiable credential in SD-JWT format. Requires a Bearer access token obtained from the token endpoint.",
    security: [%{"BearerAuth" => []}],
    request_body:
      {"Credential request", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         required: [:credential_configuration_id, :proof],
         properties: %{
           credential_configuration_id: %OpenApiSpex.Schema{
             type: :string,
             description:
               "ID of the credential configuration being requested. Must match the `credential_type` of the offer's schema.",
             example: "UniversityDegree"
           },
           proof: %OpenApiSpex.Schema{
             type: :object,
             description:
               "OID4VCI proof of possession. Currently only the `jwt` proof type is supported.",
             required: [:proof_type, :jwt],
             properties: %{
               proof_type: %OpenApiSpex.Schema{type: :string, example: "jwt"},
               jwt: %OpenApiSpex.Schema{
                 type: :string,
                 description:
                   "Compact JWS. Header: {alg: ES256, typ: openid4vci-proof+jwt, jwk: {kty,crv,x,y}}. Payload: {iss: <holder_did>, nonce: <c_nonce from /token>}. Signed with the holder key whose public coordinates are in the header `jwk`.",
                 example: "eyJhbGciOi..."
               }
             }
           }
         }
       }},
    responses: %{
      200 =>
        {"Credential issued", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             credential: %OpenApiSpex.Schema{type: :string, description: "SD-JWT credential"},
             format: %OpenApiSpex.Schema{type: :string, example: "vc+sd-jwt"}
           }
         }},
      400 =>
        {"Bad request", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      401 =>
        {"Unauthorized", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

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
        {:ok, data} ->
          json(conn, %{
            access_token: data.access_token,
            c_nonce: data.c_nonce,
            c_nonce_expires_in: data.c_nonce_expires_in,
            token_type: "bearer",
            expires_in: data.expires_in
          })

        {:error, :invalid_code} ->
          conn |> put_status(400) |> json(%{error: "invalid_grant"})

        {:error, :offer_expired} ->
          conn |> put_status(400) |> json(%{error: "expired_grant"})

        {:error, :invalid_tx_code} ->
          conn |> put_status(400) |> json(%{error: "invalid_tx_code"})

        {:error, :code_already_used} ->
          conn |> put_status(400) |> json(%{error: "invalid_grant"})

        {:error, :offer_locked} ->
          conn |> put_status(429) |> json(%{error: "too_many_attempts"})

        {:error, reason} ->
          conn |> put_status(500) |> json(%{error: inspect(reason)})
      end
    end
  end

  def issue(conn, params) do
    access_token = extract_bearer_token(conn)
    proof = params["proof"]
    credential_configuration_id = params["credential_configuration_id"]

    if is_nil(access_token) do
      conn |> put_status(401) |> json(%{error: "missing_token"})
    else
      case Issuer.issue_credential(access_token, credential_configuration_id, proof) do
        {:ok, sd_jwt} ->
          json(conn, %{credential: sd_jwt, format: "vc+sd-jwt"})

        {:error, :invalid_token} ->
          conn |> put_status(401) |> json(%{error: "invalid_token"})

        {:error, :offer_expired} ->
          conn |> put_status(400) |> json(%{error: "expired_token"})

        {:error, :invalid_proof} ->
          conn |> put_status(400) |> json(%{error: "invalid_proof"})

        {:error, :invalid_credential_request} ->
          conn |> put_status(400) |> json(%{error: "invalid_credential_request"})

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
