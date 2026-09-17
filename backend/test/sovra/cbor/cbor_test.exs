defmodule Sovra.CborTest do
  use ExUnit.Case, async: true

  alias Sovra.Cbor
  alias Sovra.Cbor.EncodeError

  defp hex(bin), do: Base.encode16(bin, case: :lower)

  describe "encode/1 — RFC 8949 Appendix A vectors" do
    test "unsigned integers pick the shortest head" do
      assert hex(Cbor.encode(0)) == "00"
      assert hex(Cbor.encode(1)) == "01"
      assert hex(Cbor.encode(10)) == "0a"
      assert hex(Cbor.encode(23)) == "17"
      assert hex(Cbor.encode(24)) == "1818"
      assert hex(Cbor.encode(100)) == "1864"
      assert hex(Cbor.encode(1000)) == "1903e8"
      assert hex(Cbor.encode(1_000_000)) == "1a000f4240"
      assert hex(Cbor.encode(1_000_000_000_000)) == "1b000000e8d4a51000"
    end

    test "negative integers" do
      assert hex(Cbor.encode(-1)) == "20"
      assert hex(Cbor.encode(-10)) == "29"
      assert hex(Cbor.encode(-100)) == "3863"
      assert hex(Cbor.encode(-1000)) == "3903e7"
    end

    test "byte strings" do
      assert hex(Cbor.encode(Cbor.bstr(<<>>))) == "40"
      assert hex(Cbor.encode(Cbor.bstr(<<1, 2, 3, 4>>))) == "4401020304"
    end

    test "text strings" do
      assert hex(Cbor.encode("")) == "60"
      assert hex(Cbor.encode("a")) == "6161"
      assert hex(Cbor.encode("IETF")) == "6449455446"
      assert hex(Cbor.encode("\"\\")) == "62225c"
    end

    test "arrays" do
      assert hex(Cbor.encode([])) == "80"
      assert hex(Cbor.encode([1, 2, 3])) == "83010203"
      assert hex(Cbor.encode([1, [2, 3], [4, 5]])) == "8301820203820405"
    end

    test "maps" do
      assert hex(Cbor.encode(%{})) == "a0"
      assert hex(Cbor.encode(%{1 => 2, 3 => 4})) == "a201020304"
      assert hex(Cbor.encode(%{"a" => 1, "b" => [2, 3]})) == "a26161016162820203"
      assert hex(Cbor.encode(["a", %{"b" => "c"}])) == "826161a161626163"
    end

    test "simple values" do
      assert hex(Cbor.encode(false)) == "f4"
      assert hex(Cbor.encode(true)) == "f5"
      assert hex(Cbor.encode(nil)) == "f6"
    end

    test "tags" do
      # #6.1004("2026-08-25")
      assert hex(Cbor.encode(Cbor.full_date("2026-08-25"))) ==
               "d903ec6a323032362d30382d3235"
    end
  end

  describe "encode/1 — deterministic map ordering" do
    test "text keys sort shortest-first, then bytewise" do
      # Insertion order is deliberately not canonical order. Encoded keys are
      # "a" -> 6161, "b" -> 6162, "bb" -> 626262, "aaa" -> 63616161, so the
      # canonical order is a, b, bb, aaa — length first, then bytewise.
      encoded = Cbor.encode(%{"bb" => 2, "a" => 1, "b" => 3, "aaa" => 4})

      assert hex(encoded) ==
               "a4" <> "616101" <> "616203" <> "62626202" <> "6361616104"
    end

    test "ordering does not depend on Erlang map iteration order" do
      # Enough keys to push the map past the small-map representation, where
      # iteration order stops matching insertion order.
      pairs = for i <- 1..64, do: {"key#{i}", i}

      forward = Map.new(pairs)
      reverse = Map.new(Enum.reverse(pairs))
      shuffled = Map.new(Enum.sort_by(pairs, fn {k, _} -> :erlang.phash2(k) end))

      assert Cbor.encode(forward) == Cbor.encode(reverse)
      assert Cbor.encode(forward) == Cbor.encode(shuffled)
    end

    test "integer keys sort by encoded form, not numeric value" do
      # COSE_Key label set. Encoded: 1 -> "01", -1 -> "20", -2 -> "21",
      # -3 -> "22". All one byte, so pure bytewise: 01 < 20 < 21 < 22.
      encoded =
        Cbor.encode(%{1 => 2, -1 => 1, -2 => Cbor.bstr(<<0xAA>>), -3 => Cbor.bstr(<<0xBB>>)})

      assert hex(encoded) == "a4" <> "0102" <> "2001" <> "2141aa" <> "2241bb"
    end

    test "RFC 7049 length-first and RFC 8949 bytewise agree on the maps mDoc emits" do
      # The two profiles differ only when a shorter encoding is bytewise
      # greater than a longer one. Pin the coincidence for our real key sets so
      # a future profile switch is a deliberate, visible change.
      key_sets = [
        # COSE header parameters
        [1, 4],
        # COSE_Key EC2 labels
        [1, -1, -2, -3],
        # MSO top level
        [
          "version",
          "digestAlgorithm",
          "valueDigests",
          "deviceKeyInfo",
          "docType",
          "validityInfo"
        ],
        # IssuerSignedItem
        ["digestID", "random", "elementIdentifier", "elementValue"],
        # digest maps are all small uints
        Enum.to_list(0..40)
      ]

      for keys <- key_sets do
        encoded = Enum.map(keys, &Cbor.encode/1)
        length_first = Enum.sort_by(encoded, &{byte_size(&1), &1})
        bytewise = Enum.sort(encoded)

        assert length_first == bytewise,
               "profiles disagree for key set #{inspect(keys)}"
      end
    end
  end

  describe "embed/1 and unwrap_embedded/1" do
    test "wraps as #6.24(bstr .cbor value)" do
      encoded = Cbor.encode(Cbor.embed([1, 2]))
      # d818 = tag 24, 43 = bstr(3), 82 01 02 = [1, 2]
      assert hex(encoded) == "d81843820102"
    end

    test "round-trips the inner bytes verbatim" do
      item = %{"digestID" => 7, "elementIdentifier" => "given_name"}
      inner = Cbor.encode(item)

      {:ok, decoded} = Cbor.decode(Cbor.encode(Cbor.embed(item)))
      assert {:ok, ^inner} = Cbor.unwrap_embedded(decoded)
    end

    test "rejects anything that is not a tag-24 wrapper" do
      assert Cbor.unwrap_embedded("plain") == :error
      assert Cbor.unwrap_embedded(%CBOR.Tag{tag: 0, value: "2026-08-25"}) == :error

      # A bare binary in the payload slot would encode as CBOR *text*, not
      # bytes, so every digest taken over it would fail. Rejected rather than
      # accepted, matching holder-core's `unwrapEmbedded`.
      assert Cbor.unwrap_embedded(%CBOR.Tag{tag: 24, value: "raw"}) == :error
    end
  end

  describe "embed_encoded/1 — the property the digest path rests on" do
    test "rebuilding a wrapper normalises non-canonical heads" do
      # 18013-5 permits only shortest-form heads, so a wrapper that arrives with
      # long-form ones — `D9 0018` for the tag, `59 xxxx` for the length — must
      # still hash to what a conformant issuer signed. This is what lets
      # verification rebuild a wrapper rather than slice the received bytes.
      item = %{"digestID" => 1, "elementIdentifier" => "tier", "elementValue" => "gold"}
      canonical = Cbor.encode(Cbor.embed(item))
      inner = Cbor.encode(item)

      long_form = <<0xD9, 0x00, 0x18, 0x59, byte_size(inner)::16>> <> inner
      refute long_form == canonical

      assert {:ok, decoded} = Cbor.decode(long_form)
      assert {:ok, ^inner} = Cbor.unwrap_embedded(decoded)
      assert Cbor.encode(Cbor.embed_encoded(inner)) == canonical

      assert :crypto.hash(:sha256, Cbor.encode(Cbor.embed_encoded(inner))) ==
               :crypto.hash(:sha256, canonical)
    end

    test "agrees with embed/1 for a value that still needs encoding" do
      value = %{"a" => 1}

      assert Cbor.encode(Cbor.embed(value)) ==
               Cbor.encode(Cbor.embed_encoded(Cbor.encode(value)))
    end
  end

  describe "encode/1 — rejections" do
    test "floats have no deterministic encoding" do
      assert_raise EncodeError, fn -> Cbor.encode(1.5) end
      assert {:error, {:unencodable, 1.5}} = Cbor.safe_encode(1.5)
    end

    test "bare atoms are rejected, so atom map keys fail loudly" do
      assert_raise EncodeError, fn -> Cbor.encode(:given_name) end
      assert {:error, {:unencodable, :given_name}} = Cbor.safe_encode(%{given_name: 1})
    end

    test "rejection reaches through nested structures" do
      assert {:error, {:unencodable, 2.5}} =
               Cbor.safe_encode(%{"a" => [1, %{"b" => 2.5}]})
    end
  end

  describe "decode/1" do
    test "round-trips the structures mDoc uses" do
      value = %{
        "version" => "1.0",
        "digestAlgorithm" => "SHA-256",
        "valueDigests" => %{"io.sovra.meta.1" => %{0 => Cbor.bstr(:binary.copy(<<7>>, 32))}},
        "flag" => true,
        "absent" => nil,
        "items" => [1, -1, "x"]
      }

      assert {:ok, decoded} = Cbor.decode(Cbor.encode(value))
      assert decoded["version"] == "1.0"
      assert decoded["flag"] == true
      assert decoded["absent"] == nil
      assert decoded["items"] == [1, -1, "x"]
      assert %CBOR.Tag{tag: :bytes, value: digest} = decoded["valueDigests"]["io.sovra.meta.1"][0]
      assert byte_size(digest) == 32
    end

    test "rejects trailing bytes" do
      assert {:error, :trailing_bytes} = Cbor.decode(Cbor.encode(1) <> <<0xFF>>)
    end

    test "rejects truncated input" do
      <<head, _rest::binary>> = Cbor.encode([1, 2, 3])
      assert {:error, _} = Cbor.decode(<<head>>)
    end

    test "rejects non-binary input" do
      assert {:error, :not_a_binary} = Cbor.decode(:nope)
    end
  end

  describe "tdate/1" do
    test "truncates to the second" do
      {:ok, dt, _} = DateTime.from_iso8601("2026-08-25T12:34:56.789Z")
      assert %CBOR.Tag{tag: 0, value: "2026-08-25T12:34:56Z"} = Cbor.tdate(dt)
    end
  end
end
