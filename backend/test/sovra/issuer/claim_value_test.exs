defmodule Sovra.Issuer.ClaimValueTest do
  use ExUnit.Case, async: true

  alias Sovra.Issuer.ClaimValue

  defp schema(claim_defs), do: %{claims: claim_defs}

  defp attachment_claim(opts \\ []) do
    %{
      "key" => Keyword.get(opts, :key, "licence_scan"),
      "type" => "attachment",
      "disclosable" => true
    }
  end

  @prefix "data:application/pdf;base64,"

  defp pdf_uri(bytes), do: @prefix <> Base.encode64(:binary.copy("%", bytes))

  # The largest PDF whose URI still fits the cap. Derived rather than written
  # down, so the test follows the cap if it moves. Base64 grows in blocks of 4,
  # so this lands on the cap exactly only when the remaining room divides evenly
  # — which it does for the current numbers, and the assertion says so.
  defp raw_bytes_at_cap do
    div(ClaimValue.max_attachment_uri_bytes() - byte_size(@prefix), 4) * 3
  end

  describe "types this does not govern" do
    # The dashboard sends every value as a string, so a `number` claim arrives
    # as "42". Type-checking everything would reject values that issue perfectly
    # well today — this is the regression guard for that, and it is the reason
    # the module inspects one type rather than all of them.
    test "a number claim carrying a string is accepted" do
      defs = [%{"key" => "age", "type" => "number", "disclosable" => true}]
      assert :ok = ClaimValue.validate(schema(defs), %{"age" => "42"})
    end

    test "an unknown type carrying anything is accepted" do
      defs = [%{"key" => "whatever", "type" => "something_new", "disclosable" => true}]
      assert :ok = ClaimValue.validate(schema(defs), %{"whatever" => %{"nested" => [1, 2]}})
    end

    test "a claim the caller did not send is not this function's problem" do
      # `ClaimUtils.validate_required_claims/2` owns presence.
      assert :ok = ClaimValue.validate(schema([attachment_claim()]), %{})
    end
  end

  describe "attachment" do
    test "accepts a PDF data URI" do
      claims = %{"licence_scan" => pdf_uri(1024)}
      assert :ok = ClaimValue.validate(schema([attachment_claim()]), claims)
    end

    test "accepts a URI exactly at the cap" do
      uri = pdf_uri(raw_bytes_at_cap())
      assert byte_size(uri) == ClaimValue.max_attachment_uri_bytes()
      assert :ok = ClaimValue.validate(schema([attachment_claim()]), %{"licence_scan" => uri})
    end

    test "rejects the next PDF size up" do
      uri = pdf_uri(raw_bytes_at_cap() + 3)
      assert byte_size(uri) > ClaimValue.max_attachment_uri_bytes()

      assert {:error, {:invalid_claim_values, [{"licence_scan", :too_large}]}} =
               ClaimValue.validate(schema([attachment_claim()]), %{"licence_scan" => uri})
    end

    test "rejects a media type that is not on the list" do
      claims = %{"licence_scan" => "data:image/png;base64," <> Base.encode64("png")}

      assert {:error, {:invalid_claim_values, [{"licence_scan", :unsupported_media_type}]}} =
               ClaimValue.validate(schema([attachment_claim()]), claims)
    end

    test "rejects bare base64 with no data: prefix" do
      claims = %{"licence_scan" => Base.encode64("%PDF-1.7")}

      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_data_uri}]}} =
               ClaimValue.validate(schema([attachment_claim()]), claims)
    end

    test "rejects embedded whitespace" do
      # Legal inside a base64 body, illegal inside a data: URI. Stripping it
      # would mean revalidating the result, so it is refused instead.
      claims = %{"licence_scan" => "data:application/pdf;base64,JVBE Ri0x"}

      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_data_uri}]}} =
               ClaimValue.validate(schema([attachment_claim()]), claims)
    end

    test "rejects the base64url alphabet" do
      claims = %{"licence_scan" => "data:application/pdf;base64,_-_-"}

      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_data_uri}]}} =
               ClaimValue.validate(schema([attachment_claim()]), claims)
    end

    test "rejects a trailing newline" do
      # `base64 -w0` ends its output with one, and PCRE's `$` would let it
      # through — while the wallet's parser would not recognise the value as a
      # document and keep the whole URI in its credential index.
      claims = %{"licence_scan" => pdf_uri(16) <> "\n"}

      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_data_uri}]}} =
               ClaimValue.validate(schema([attachment_claim()]), claims)
    end

    test "rejects a payload in the right alphabet that does not decode" do
      for payload <- ["A", "AAAAA", Base.encode64("%PDF") |> String.trim_trailing("=")] do
        claims = %{"licence_scan" => @prefix <> payload}

        assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_data_uri}]}} =
                 ClaimValue.validate(schema([attachment_claim()]), claims)
      end
    end

    test "rejects an empty string" do
      # The console omits an attachment the operator left empty; "" is not a
      # document, and accepting it would be a second way to say "none".
      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_data_uri}]}} =
               ClaimValue.validate(schema([attachment_claim()]), %{"licence_scan" => ""})
    end

    test "reads nil on an optional attachment as not sent" do
      # `SDJWT.split_claims/2` drops a nil value, so this issues exactly as
      # leaving the key out does.
      assert :ok = ClaimValue.validate(schema([attachment_claim()]), %{"licence_scan" => nil})
    end

    test "refuses nil on a required attachment" do
      # `validate_required_claims/2` only checks the key is there, so this is the
      # one place a required document sent as null is caught.
      defs = [Map.put(attachment_claim(), "required", true)]

      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_string}]}} =
               ClaimValue.validate(schema(defs), %{"licence_scan" => nil})
    end

    test "rejects a non-string" do
      claims = %{"licence_scan" => %{"uri" => pdf_uri(16)}}

      assert {:error, {:invalid_claim_values, [{"licence_scan", :not_a_string}]}} =
               ClaimValue.validate(schema([attachment_claim()]), claims)
    end

    test "names every claim that failed" do
      defs = [attachment_claim(key: "front"), attachment_claim(key: "back")]
      claims = %{"front" => "nope", "back" => pdf_uri(16)}

      assert {:error, {:invalid_claim_values, [{"front", :not_a_data_uri}]}} =
               ClaimValue.validate(schema(defs), claims)
    end
  end

  describe "describe/1" do
    test "reports the media type and the decoded size" do
      assert {:ok, %{media_type: "application/pdf", bytes: 3000}} =
               ClaimValue.describe(pdf_uri(3000))
    end

    test "gets the size right across every padding length" do
      for bytes <- [1, 2, 3, 4, 5, 6, 100, 101, 102] do
        assert {:ok, %{bytes: ^bytes}} = ClaimValue.describe(pdf_uri(bytes))
      end
    end

    test "refuses anything that is not a data URI" do
      assert :error = ClaimValue.describe("https://example.gov/licence.pdf")
      assert :error = ClaimValue.describe(nil)
      assert :error = ClaimValue.describe(42)
    end
  end
end
