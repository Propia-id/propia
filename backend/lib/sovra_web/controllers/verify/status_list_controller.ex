defmodule SovraWeb.Verify.StatusListController do
  use SovraWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias Sovra.Credentials.BitstringStatusList
  alias Sovra.Ethereum.RevocationRegistry
  alias Sovra.Issuer.IssuerRecord
  alias Sovra.Repo

  tags(["Status List"])

  operation(:show,
    summary: "Get credential status list",
    description:
      "Fetch the W3C Bitstring Status List credential for an issuer and purpose. " <>
        "Verifiers use this endpoint to cache status lists for offline verification.",
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
        {"Status list credential", "application/json",
         %OpenApiSpex.Schema{
           type: :object,
           properties: %{
             "@context": %OpenApiSpex.Schema{
               type: :array,
               items: %OpenApiSpex.Schema{type: :string}
             },
             type: %OpenApiSpex.Schema{type: :array, items: %OpenApiSpex.Schema{type: :string}},
             issuer: %OpenApiSpex.Schema{type: :string},
             validFrom: %OpenApiSpex.Schema{type: :string, format: :"date-time"},
             credentialSubject: %OpenApiSpex.Schema{
               type: :object,
               properties: %{
                 type: %OpenApiSpex.Schema{type: :string},
                 statusPurpose: %OpenApiSpex.Schema{type: :string},
                 encodedList: %OpenApiSpex.Schema{type: :string}
               }
             }
           }
         }},
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
    with {:ok, purpose_int} <- validate_purpose(purpose),
         {:ok, issuer} <- find_issuer(issuer_did),
         {:ok, bitmap_words} <- RevocationRegistry.get_bitmap(issuer.eoa_address, purpose_int) do
      encoded_list = BitstringStatusList.encode(bitmap_words)
      credential = BitstringStatusList.build_credential(issuer.did, purpose, encoded_list)

      conn
      |> put_resp_header("cache-control", "public, max-age=300")
      |> json(credential)
    else
      {:error, :invalid_purpose} ->
        conn |> put_status(400) |> json(%{error: "invalid_purpose"})

      {:error, :issuer_not_found} ->
        conn |> put_status(404) |> json(%{error: "issuer_not_found"})

      {:error, reason} ->
        conn |> put_status(500) |> json(%{error: to_string(reason)})
    end
  end

  defp validate_purpose(purpose) do
    case Map.fetch(@purpose_map, purpose) do
      {:ok, int} -> {:ok, int}
      :error -> {:error, :invalid_purpose}
    end
  end

  defp find_issuer(did) do
    case Repo.get_by(IssuerRecord, did: did) do
      nil -> {:error, :issuer_not_found}
      issuer -> {:ok, issuer}
    end
  end
end
