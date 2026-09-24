defmodule Sovra.Issuer.SDJWTAttachmentTest do
  use ExUnit.Case, async: true

  alias Sovra.Issuer.SDJWT

  @pdf "data:application/pdf;base64," <> Base.encode64("%PDF-1.7 pretend this is a licence")

  defp disclosure(key, value) do
    Jason.encode!(["saltsaltsalt", key, value]) |> Base.url_encode64(padding: false)
  end

  defp sd_jwt(disclosures), do: Enum.join(["header.payload.signature" | disclosures], "~") <> "~"

  describe "without_claim/2" do
    test "removes exactly the named disclosure and leaves the rest in order" do
      name = disclosure("family_name", "Bilbao")
      scan = disclosure("licence_scan", @pdf)
      number = disclosure("document_number", "X-1")

      {stripped, described} = SDJWT.without_claim(sd_jwt([name, scan, number]), "licence_scan")

      assert stripped == sd_jwt([name, number])
      refute stripped =~ "application/pdf"
      assert described["claim"] == "licence_scan"
      assert described["media_type"] == "application/pdf"
      assert described["bytes"] == byte_size("%PDF-1.7 pretend this is a licence")
    end

    test "leaves the issuer JWT byte-identical" do
      # The signature covers the JWT alone, so removing a disclosure has to
      # leave it untouched — that is what makes the removal an ordinary
      # withheld claim rather than a broken credential.
      original = sd_jwt([disclosure("licence_scan", @pdf)])
      {stripped, _} = SDJWT.without_claim(original, "licence_scan")

      assert hd(String.split(stripped, "~")) == hd(String.split(original, "~"))
    end

    test "returns the credential untouched when it carries no such claim" do
      original = sd_jwt([disclosure("family_name", "Bilbao")])

      assert {^original, nil} = SDJWT.without_claim(original, "licence_scan")
    end

    test "describes nothing when the disclosure is not an attachment" do
      original = sd_jwt([disclosure("family_name", "Bilbao")])

      assert {stripped, nil} = SDJWT.without_claim(original, "family_name")
      assert stripped == sd_jwt([])
    end

    test "leaves a KB-JWT alone" do
      # A presentation ends in a KB-JWT rather than an empty segment. It does
      # not decode as a [salt, key, value] array, so it is never mistaken for a
      # disclosure and removed.
      presentation =
        "header.payload.signature~" <> disclosure("licence_scan", @pdf) <> "~kb.jwt.sig"

      {stripped, described} = SDJWT.without_claim(presentation, "licence_scan")

      assert stripped == "header.payload.signature~kb.jwt.sig"
      assert described["media_type"] == "application/pdf"
    end

    test "survives a credential with no disclosures at all" do
      assert {"header.payload.signature~", nil} =
               SDJWT.without_claim("header.payload.signature~", "licence_scan")
    end
  end

  describe "build_preview/4" do
    defp issuer, do: %{did: "did:sovra:0xabc", signing_key_id: "unused"}

    defp schema(claim_defs) do
      %{
        claims: claim_defs,
        credential_type: "DrivingLicence",
        validity_period: "5y"
      }
    end

    test "describes an attachment instead of echoing it" do
      # The preview goes back in the response to the request that just uploaded
      # the PDF. Echoing it buys nothing and doubles the response.
      defs = [
        %{"key" => "family_name", "type" => "string", "disclosable" => true},
        %{"key" => "licence_scan", "type" => "attachment", "disclosable" => true}
      ]

      preview =
        SDJWT.build_preview(issuer(), schema(defs), %{
          "family_name" => "Bilbao",
          "licence_scan" => @pdf
        })

      assert preview["family_name"] == "Bilbao"
      refute inspect(preview) =~ "application/pdf;base64"

      assert preview["licence_scan"] == %{
               "type" => "attachment",
               "media_type" => "application/pdf",
               "bytes" => byte_size("%PDF-1.7 pretend this is a licence")
             }
    end

    test "leaves every other claim as it stands" do
      defs = [%{"key" => "tier", "type" => "string", "disclosable" => true}]
      preview = SDJWT.build_preview(issuer(), schema(defs), %{"tier" => "gold"})

      assert preview["tier"] == "gold"
    end
  end
end
