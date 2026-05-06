defmodule SovraWeb.Verify.StatusListController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Credentials.BitstringStatusList
  alias Sovra.Repo
  alias Sovra.Workspaces.Workspace

  tags(["Status List"])

  operation(:show,
    summary: "Get credential status list",
    description:
      "Fetch the W3C Bitstring Status List credential (VC-JWT, ES256-signed) " <>
        "for an issuer and purpose. Verifiers cache the response by ETag.",
    parameters: [
      issuer_did: [
        in: :path,
        type: :string,
        description: "Issuer DID (did:sovra:0x...)",
        required: true
      ],
      purpose: [
        in: :path,
        type: :string,
        description: "Status purpose: revocation or suspension",
        required: true
      ]
    ],
    responses: %{
      200 =>
        {"Signed status list credential (compact JWS)", "application/jwt",
         %OpenApiSpex.Schema{type: :string, format: "jwt"}},
      304 => {"Not modified", "application/jwt", %OpenApiSpex.Schema{type: :string}},
      400 =>
        {"Invalid purpose", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }},
      404 =>
        {"Issuer not found", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{error: %OpenApiSpex.Schema{type: :string}}
         }}
    }
  )

  @purpose_map %{"revocation" => 0, "suspension" => 1}

  def show(conn, %{"issuer_did" => issuer_did, "purpose" => purpose}) do
    registry = revocation_registry()

    with {:ok, purpose_int} <- validate_purpose(purpose),
         {:ok, workspace} <- find_issuer(issuer_did),
         {:ok, bitmap_words} <- registry.get_bitmap(workspace.eoa_address, purpose_int) do
      encoded_list = BitstringStatusList.encode(bitmap_words)
      signing_input = BitstringStatusList.build_signing_input(workspace, purpose, encoded_list)
      etag = compute_etag(signing_input)

      conn =
        conn
        |> put_resp_header("etag", etag)
        |> put_resp_header(
          "cache-control",
          "public, max-age=#{BitstringStatusList.iat_bucket_seconds()}"
        )

      if etag in get_req_header(conn, "if-none-match") do
        send_resp(conn, 304, "")
      else
        case BitstringStatusList.sign(workspace, signing_input) do
          {:ok, jwt} ->
            conn
            |> put_resp_content_type("application/jwt")
            |> send_resp(200, jwt)

          {:error, reason} ->
            conn |> put_status(500) |> json(%{error: to_string(reason)})
        end
      end
    else
      {:error, :invalid_purpose} ->
        conn |> put_status(400) |> json(%{error: "invalid_purpose"})

      {:error, :issuer_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})

      {:error, reason} ->
        conn |> put_status(500) |> json(%{error: to_string(reason)})
    end
  end

  # ETag covers the signing input (header.payload), not the signature.
  # ES256 signatures are non-deterministic — each sign call samples a fresh k,
  # so two JWTs over identical state will have different bytes. Hashing the
  # signing input lets us short-circuit on If-None-Match without ever paying
  # for a signature.
  defp compute_etag(signing_input) do
    digest = :crypto.hash(:sha256, signing_input) |> Base.encode16(case: :lower)
    ~s("#{digest}")
  end

  defp revocation_registry do
    Application.get_env(:sovra, :revocation_registry, Sovra.Ethereum.RevocationRegistry)
  end

  defp validate_purpose(purpose) do
    case Map.fetch(@purpose_map, purpose) do
      {:ok, int} -> {:ok, int}
      :error -> {:error, :invalid_purpose}
    end
  end

  defp find_issuer(did) do
    case Repo.get_by(Workspace, did: did) do
      nil -> {:error, :issuer_not_found}
      workspace -> {:ok, workspace}
    end
  end
end
