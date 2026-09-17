defmodule Sovra.Issuer.MdocElement do
  @moduledoc """
  Maps a schema claim onto the CBOR value that goes into an `IssuerSignedItem`.

  SD-JWT carries claim values as JSON, so anything JSON can express issues
  fine. CBOR is stricter in one direction and richer in another: dates get
  proper tags rather than being strings by convention, and floats have no
  deterministic encoding at all.

  That last one is why `encodable?/2` exists. A non-integral `number` cannot be
  encoded, and discovering it at delivery time would surface as a 500 in the
  middle of the holder's wallet flow, long after the operator has gone. Checked
  at offer creation instead, it is a 422 on the request that introduced it.
  """

  alias Sovra.Cbor
  alias Sovra.Issuer.ClaimUtils

  @known_types ~w(string uri integer boolean number date datetime bytes driving_privileges)

  @doc "The claim types a schema may declare. `Sovra.Mdl.Template` names which ones an mDL uses."
  def known_types, do: @known_types

  @doc """
  Encode one claim value according to its schema-declared type.

  Returns `{:error, {:unencodable_claim, key}}` rather than guessing, because a
  wrong guess here is a credential that verifies but says something false.
  """
  @spec encode(map(), term()) :: {:ok, term()} | {:error, {:unencodable_claim, String.t()}}
  def encode(%{"key" => key} = claim_def, value) do
    case do_encode(claim_def["type"], value) do
      {:ok, _} = ok -> ok
      :error -> {:error, {:unencodable_claim, key}}
    end
  end

  @doc """
  Whether every claim the schema declares can be encoded from `claims`.

  A no-op for `vc+sd-jwt` schemas — JSON has no equivalent restriction, and
  applying one would reject values that issue perfectly well today.
  """
  @spec encodable?(map(), map()) :: :ok | {:error, {:unencodable_claims, [String.t()]}}
  def encodable?(%{format: "mso_mdoc"} = schema, claims) do
    unencodable =
      schema.claims
      |> ClaimUtils.parse_claim_defs()
      |> Enum.filter(fn claim_def ->
        case Map.fetch(claims, claim_def["key"]) do
          {:ok, value} -> match?(:error, do_encode(claim_def["type"], value))
          :error -> false
        end
      end)
      |> Enum.map(& &1["key"])

    case unencodable do
      [] -> :ok
      keys -> {:error, {:unencodable_claims, keys}}
    end
  end

  def encodable?(_schema, _claims), do: :ok

  # Text-shaped types.
  defp do_encode(type, value) when type in ["string", "uri"] and is_binary(value),
    do: {:ok, value}

  defp do_encode("integer", value) when is_integer(value), do: {:ok, value}

  defp do_encode("boolean", value) when is_boolean(value), do: {:ok, value}

  # `number` is the only schema type that can carry a float. Integral values
  # encode as integers; anything else has no deterministic CBOR form, and
  # inventing one would mean a verifier could hash the same credential
  # differently than we signed it.
  defp do_encode("number", value) when is_integer(value), do: {:ok, value}

  defp do_encode("number", value) when is_float(value) do
    if trunc(value) == value, do: {:ok, trunc(value)}, else: :error
  end

  # ISO 18013-5 dates are tagged, not stringly typed.
  defp do_encode("date", <<_::binary-size(10)>> = value) do
    case Date.from_iso8601(value) do
      {:ok, _} -> {:ok, Cbor.full_date(value)}
      _ -> :error
    end
  end

  defp do_encode("datetime", value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _offset} -> {:ok, Cbor.tdate(dt)}
      _ -> :error
    end
  end

  defp do_encode("datetime", %DateTime{} = value), do: {:ok, Cbor.tdate(value)}

  # A byte string — `portrait`, `signature_usual_mark`, a biometric template.
  # Base64 in, because the claim arrives as JSON and JSON has no bytes; the
  # credential carries the decoded bytes, so a wallet renders the image the
  # issuer supplied rather than a base64 string that happens to look like one.
  #
  # Standard alphabet with padding, and only that: this is an API request body,
  # not a URL, and accepting four spellings of the same value is how two
  # issuers end up disagreeing about what they sent.
  defp do_encode("bytes", value) when is_binary(value) do
    case Base.decode64(value) do
      {:ok, bytes} -> {:ok, Cbor.bstr(bytes)}
      :error -> :error
    end
  end

  # ISO 18013-5 §7.2.4. An array of driving privilege entries, each naming a
  # vehicle category and optionally when it was issued, when it expires, and
  # any restriction codes on it.
  #
  # Encoded field by field rather than passed through, because the dates are
  # tagged `full-date` values inside a nested structure. A generic
  # array-of-objects type would carry them as strings, producing a credential
  # that verifies and that no conformant reader can read the dates out of.
  defp do_encode("driving_privileges", value) when is_list(value) do
    encode_each(value, &driving_privilege/1)
  end

  # A type this module *does* know, carrying a value of the wrong shape, is an
  # error rather than a coercion. Letting a string through for an integer claim
  # would produce a credential that verifies and says something false.
  defp do_encode(type, _value) when type in @known_types, do: :error

  # An unfamiliar type falls through to text when the value is already a
  # string, so a schema using a type this module has not learned yet still
  # issues. Anything else is refused.
  defp do_encode(_type, value) when is_binary(value), do: {:ok, value}
  defp do_encode(_type, _value), do: :error

  # ── Driving privileges ──────────────────────────────────

  # `vehicle_category_code` is the only mandatory member. The dates are
  # optional per ISO, and `codes` is an array of restriction/condition entries
  # whose `code` is likewise the only mandatory one.
  defp driving_privilege(%{"vehicle_category_code" => category} = entry)
       when is_binary(category) and category != "" do
    with {:ok, issue_date} <- optional_full_date(entry, "issue_date"),
         {:ok, expiry_date} <- optional_full_date(entry, "expiry_date"),
         {:ok, codes} <- optional_codes(entry) do
      {:ok,
       %{"vehicle_category_code" => category}
       |> put_present("issue_date", issue_date)
       |> put_present("expiry_date", expiry_date)
       |> put_present("codes", codes)}
    end
  end

  defp driving_privilege(_entry), do: :error

  defp optional_codes(entry) do
    case Map.get(entry, "codes") do
      nil -> {:ok, nil}
      codes when is_list(codes) -> encode_each(codes, &privilege_code/1)
      _ -> :error
    end
  end

  # `sign` and `value` qualify a code — ISO's example is a code with sign "<="
  # and value "70" for a maximum speed. Both are text, not numbers.
  defp privilege_code(%{"code" => code} = entry) when is_binary(code) and code != "" do
    with {:ok, sign} <- optional_string(entry, "sign"),
         {:ok, value} <- optional_string(entry, "value") do
      {:ok,
       %{"code" => code}
       |> put_present("sign", sign)
       |> put_present("value", value)}
    end
  end

  defp privilege_code(_entry), do: :error

  defp optional_full_date(entry, key) do
    case Map.get(entry, key) do
      nil -> {:ok, nil}
      value -> do_encode("date", value)
    end
  end

  defp optional_string(entry, key) do
    case Map.get(entry, key) do
      nil -> {:ok, nil}
      value when is_binary(value) -> {:ok, value}
      _ -> :error
    end
  end

  # An empty list is refused along with a malformed one: ISO requires at least
  # one driving privilege, and an mDL claiming none is a licence to drive
  # nothing.
  defp encode_each([], _fun), do: :error

  defp encode_each(list, fun) do
    Enum.reduce_while(list, {:ok, []}, fn entry, {:ok, acc} ->
      case entry do
        %{} = map ->
          case fun.(map) do
            {:ok, encoded} -> {:cont, {:ok, [encoded | acc]}}
            :error -> {:halt, :error}
          end

        _ ->
          {:halt, :error}
      end
    end)
    |> case do
      {:ok, encoded} -> {:ok, Enum.reverse(encoded)}
      :error -> :error
    end
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)
end
