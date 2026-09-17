defmodule Sovra.Issuer.MdocElementTest do
  use ExUnit.Case, async: true

  alias Sovra.Cbor
  alias Sovra.Issuer.MdocElement

  defp encode(type, value), do: MdocElement.encode(%{"key" => "k", "type" => type}, value)

  # What the issuer signs is the CBOR, so a round trip is the assertion that
  # matters — an encoder that returns a plausible term and encodes to something
  # else is exactly the failure these types exist to prevent.
  defp round_trip(value) do
    {:ok, decoded} = value |> Cbor.encode() |> Cbor.decode()
    decoded
  end

  describe "bytes" do
    test "decodes base64 into a CBOR byte string" do
      # A `portrait` has to reach the wallet as bytes. Carried as text it would
      # verify perfectly and render as a wall of base64.
      photo = <<0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10>>

      assert {:ok, encoded} = encode("bytes", Base.encode64(photo))
      assert %CBOR.Tag{tag: :bytes, value: ^photo} = encoded
      assert %CBOR.Tag{tag: :bytes, value: ^photo} = round_trip(encoded)
    end

    test "rejects a value that is not base64" do
      assert {:error, {:unencodable_claim, "k"}} = encode("bytes", "not base64!!")
    end

    test "rejects the base64url alphabet" do
      # One spelling only. This arrives in an API request body, not a URL, and
      # accepting four ways to write the same bytes is how two issuers end up
      # disagreeing about what they sent.
      assert {:error, _} = encode("bytes", "_-_-")
    end

    test "rejects a non-string" do
      assert {:error, _} = encode("bytes", 42)
    end
  end

  describe "driving_privileges" do
    test "encodes a full entry, tagging the dates inside it" do
      # The reason this is a named type rather than a generic array of objects:
      # the dates are tagged `full-date` values nested inside the structure, and
      # a pass-through encoder would carry them as strings.
      assert {:ok, [entry]} =
               encode("driving_privileges", [
                 %{
                   "vehicle_category_code" => "B",
                   "issue_date" => "2020-03-01",
                   "expiry_date" => "2030-03-01",
                   "codes" => [%{"code" => "S01", "sign" => "<=", "value" => "70"}]
                 }
               ])

      assert entry["vehicle_category_code"] == "B"
      assert %CBOR.Tag{tag: 1004, value: "2020-03-01"} = entry["issue_date"]
      assert %CBOR.Tag{tag: 1004, value: "2030-03-01"} = entry["expiry_date"]
      assert [%{"code" => "S01", "sign" => "<=", "value" => "70"}] = entry["codes"]

      assert [%{"issue_date" => %CBOR.Tag{tag: 1004}}] = round_trip([entry])
    end

    test "omits what the entry does not carry rather than writing nulls" do
      # Every member but the category is optional per ISO, and a key present
      # with a null value is not the same as an absent key — it is a digest over
      # different bytes, asserting the issuer said something about it.
      assert {:ok, [entry]} =
               encode("driving_privileges", [%{"vehicle_category_code" => "AM"}])

      assert entry == %{"vehicle_category_code" => "AM"}
    end

    test "encodes several categories in the order given" do
      assert {:ok, entries} =
               encode("driving_privileges", [
                 %{"vehicle_category_code" => "A"},
                 %{"vehicle_category_code" => "B"}
               ])

      assert Enum.map(entries, & &1["vehicle_category_code"]) == ["A", "B"]
    end

    test "rejects an entry with no vehicle category" do
      assert {:error, _} = encode("driving_privileges", [%{"issue_date" => "2020-03-01"}])
    end

    test "rejects an empty list" do
      # ISO requires at least one privilege, and an mDL claiming none is a
      # licence to drive nothing.
      assert {:error, _} = encode("driving_privileges", [])
    end

    test "rejects a malformed date inside an entry" do
      assert {:error, _} =
               encode("driving_privileges", [
                 %{"vehicle_category_code" => "B", "issue_date" => "01/03/2020"}
               ])
    end

    test "rejects a code with no code" do
      assert {:error, _} =
               encode("driving_privileges", [
                 %{"vehicle_category_code" => "B", "codes" => [%{"sign" => "<="}]}
               ])
    end

    test "rejects a bare string" do
      assert {:error, _} = encode("driving_privileges", "B")
    end
  end

  describe "encodable?/2" do
    test "names every claim that cannot be encoded, at offer time" do
      # The whole point of the check: a value with no deterministic CBOR form
      # would otherwise surface as a 500 in the middle of a holder's wallet
      # flow, long after the operator who supplied it has gone.
      schema = %{
        format: "mso_mdoc",
        claims: [
          %{"key" => "portrait", "type" => "bytes"},
          %{"key" => "driving_privileges", "type" => "driving_privileges"},
          %{"key" => "family_name", "type" => "string"}
        ]
      }

      claims = %{
        "portrait" => "not base64!!",
        "driving_privileges" => [],
        "family_name" => "Lovelace"
      }

      assert {:error, {:unencodable_claims, keys}} = MdocElement.encodable?(schema, claims)
      assert Enum.sort(keys) == ["driving_privileges", "portrait"]
    end
  end
end
