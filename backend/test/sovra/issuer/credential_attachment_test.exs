defmodule Sovra.Issuer.CredentialAttachmentTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  alias Sovra.Crypto.P256
  alias Sovra.Issuer
  alias Sovra.Issuer.ClaimValue
  alias Sovra.Issuer.CredentialOffer
  alias Sovra.Repo
  alias Sovra.Webhooks.DeliveryJob

  @pdf_bytes "%PDF-1.7 pretend this is a scanned driving licence"
  @pdf "data:application/pdf;base64," <> Base.encode64(@pdf_bytes)

  defp issuer_workspace do
    workspace = provision_workspace(fixture_workspace().workspace)
    fixture_webhook(workspace)
    workspace
  end

  defp attachment_schema(workspace) do
    {:ok, schema} =
      Issuer.create_schema(workspace.id, %{
        schema_id: "licence-#{System.unique_integer([:positive])}",
        credential_type: "DrivingLicence#{System.unique_integer([:positive])}",
        name: "Driving Licence",
        claims: [
          %{
            "key" => "family_name",
            "type" => "string",
            "required" => true,
            "disclosable" => true
          },
          %{"key" => "licence_scan", "type" => "attachment", "disclosable" => true}
        ],
        validity_period: "5y"
      })

    register_schema(schema)
  end

  defp holder_proof(c_nonce) do
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
    {:ok, %{r: r, s: s}} = P256.sign(:crypto.hash(:sha256, signing_input), priv)
    sig = P256.pad_or_trim(r, 32) <> P256.pad_or_trim(s, 32)

    %{
      "proof_type" => "jwt",
      "jwt" => "#{signing_input}.#{Base.url_encode64(sig, padding: false)}"
    }
  end

  defp issue(workspace, schema, claims) do
    {:ok, offer} = Issuer.create_credential_offer(workspace.id, schema.schema_id, claims)
    {:ok, token} = Issuer.exchange_token(offer.pre_authorized_code)

    {:ok, %{credential: credential}} =
      Issuer.issue_credential(
        token.access_token,
        schema.credential_type,
        holder_proof(token.c_nonce)
      )

    {offer, credential}
  end

  defp disclosures(sd_jwt) do
    sd_jwt
    |> String.split("~")
    |> Enum.drop(1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.map(&(&1 |> Base.url_decode64!(padding: false) |> Jason.decode!()))
  end

  describe "create_credential_offer/3" do
    test "refuses an oversize attachment without creating an offer" do
      workspace = issuer_workspace()
      schema = attachment_schema(workspace)
      before = Repo.aggregate(CredentialOffer, :count)

      huge =
        "data:application/pdf;base64," <>
          Base.encode64(:binary.copy("%", ClaimValue.max_attachment_uri_bytes()))

      assert {:error, {:invalid_claim_values, [{"licence_scan", :too_large}]}} =
               Issuer.create_credential_offer(workspace.id, schema.schema_id, %{
                 "family_name" => "Bilbao",
                 "licence_scan" => huge
               })

      # The check runs before the insert, so a rejected PDF never sits in
      # `credential_offers.claims` waiting for the offer to expire.
      assert Repo.aggregate(CredentialOffer, :count) == before
    end

    test "refuses a value that is not a PDF data URI" do
      workspace = issuer_workspace()
      schema = attachment_schema(workspace)

      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_data_uri}]}} =
               Issuer.create_credential_offer(workspace.id, schema.schema_id, %{
                 "family_name" => "Bilbao",
                 "licence_scan" => "https://example.gov/licence.pdf"
               })
    end

    test "the preview describes the attachment rather than echoing it" do
      workspace = issuer_workspace()
      schema = attachment_schema(workspace)

      {:ok, result} =
        Issuer.create_credential_offer(workspace.id, schema.schema_id, %{
          "family_name" => "Bilbao",
          "licence_scan" => @pdf
        })

      refute inspect(result.credential) =~ "application/pdf;base64"
      assert result.credential["family_name"] == "Bilbao"

      assert result.credential["licence_scan"] == %{
               "type" => "attachment",
               "media_type" => "application/pdf",
               "bytes" => byte_size(@pdf_bytes)
             }
    end
  end

  describe "the issued credential" do
    test "carries the attachment as a disclosure, not in the signed payload" do
      workspace = issuer_workspace()
      schema = attachment_schema(workspace)

      {_offer, credential} =
        issue(workspace, schema, %{"family_name" => "Bilbao", "licence_scan" => @pdf})

      [jwt | _] = String.split(credential, "~")
      [_, payload_b64, _] = String.split(jwt, ".")
      payload = payload_b64 |> Base.url_decode64!(padding: false) |> Jason.decode!()

      # Flat in the payload would mean the holder could never withhold it.
      refute Map.has_key?(payload, "licence_scan")
      assert length(payload["_sd"]) == 2

      assert Enum.any?(disclosures(credential), fn [_salt, key, value] ->
               key == "licence_scan" and value == @pdf
             end)
    end
  end

  describe "the credential.issued webhook" do
    test "ships a description of the attachment, not the bytes" do
      # The whole credential goes into the body, retried eight times against an
      # endpoint with a five-second timeout — and the consumer uploaded this PDF
      # minutes ago.
      workspace = issuer_workspace()
      schema = attachment_schema(workspace)

      {_offer, credential} =
        issue(workspace, schema, %{"family_name" => "Bilbao", "licence_scan" => @pdf})

      [job] =
        all_enqueued(worker: DeliveryJob)
        |> Enum.filter(&(&1.args["payload"]["event"] == "credential.issued"))
        |> Enum.take(1)

      payload = job.args["payload"]["data"] || job.args["payload"]

      shipped = payload["credential"]
      refute shipped =~ "application/pdf;base64"
      assert shipped =~ hd(String.split(credential, "~"))

      assert payload["attachment"] == %{
               "claim" => "licence_scan",
               "type" => "attachment",
               "media_type" => "application/pdf",
               "bytes" => byte_size(@pdf_bytes)
             }

      # The other disclosure is untouched: only the attachment is withheld.
      assert Enum.any?(disclosures(shipped), fn [_salt, key, _value] ->
               key == "family_name"
             end)
    end

    test "a credential with no attachment ships exactly as it always did" do
      workspace = issuer_workspace()

      {:ok, schema} =
        Issuer.create_schema(workspace.id, %{
          schema_id: "plain-#{System.unique_integer([:positive])}",
          credential_type: "Plain#{System.unique_integer([:positive])}",
          name: "Plain",
          claims: [
            %{"key" => "family_name", "type" => "string", "disclosable" => true}
          ],
          validity_period: "1y"
        })

      schema = register_schema(schema)

      {_offer, credential} = issue(workspace, schema, %{"family_name" => "Bilbao"})

      [job] =
        all_enqueued(worker: DeliveryJob)
        |> Enum.filter(&(&1.args["payload"]["event"] == "credential.issued"))
        |> Enum.take(1)

      payload = job.args["payload"]["data"] || job.args["payload"]

      assert payload["credential"] == credential
      refute Map.has_key?(payload, "attachment")
    end
  end
end
