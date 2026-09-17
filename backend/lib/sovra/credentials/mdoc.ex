defmodule Sovra.Credentials.Mdoc do
  @moduledoc """
  Pure parsing and verification for ISO 18013-5 `DeviceResponse` — the mdoc
  sibling of `Sovra.Credentials.SDJWT`.

  Session-free by design: everything here takes bytes and keys and returns data.
  Orchestration, session finalization and webhooks stay in
  `Sovra.Verification.Verifier`, which is what lets both formats share the same
  failure handling.

  ## Verbatim bytes, again

  Every parsed item keeps the `#6.24(bstr .cbor IssuerSignedItem)` bytes exactly
  as received, and digests are computed over those. The CBOR decoder is lossy —
  tag 0 becomes a `DateTime`, tags 2 and 3 become integers — so re-encoding a
  decoded item would not reproduce what the issuer signed.
  """

  alias Sovra.Cbor
  alias Sovra.Cose

  @doc """
  Parse a base64url-encoded `DeviceResponse`.

  Requires `status: 0` and exactly one document. More than one would mean the
  holder answered a question we did not ask, and picking one of them is the kind
  of guess that turns into a vulnerability.
  """
  @spec parse_device_response(binary()) :: {:ok, map()} | {:error, atom()}
  def parse_device_response(b64) when is_binary(b64) do
    with {:ok, bytes} <- decode_b64(b64),
         {:ok, response} when is_map(response) <- Cbor.decode(bytes),
         0 <- Map.get(response, "status"),
         [document] <- Map.get(response, "documents"),
         {:ok, parsed} <- parse_document(document) do
      {:ok, parsed}
    else
      _ -> {:error, :malformed_vp_token}
    end
  end

  def parse_device_response(_), do: {:error, :malformed_vp_token}

  @doc """
  Verify `issuerAuth` and return the decoded MSO.

  Requires ES256 in the *protected* header. An `alg` in the unprotected header
  carries no authority, and honouring one would let a holder choose the
  verification path.
  """
  @spec verify_issuer_auth(map(), {binary(), binary()}) :: {:ok, map()} | {:error, atom()}
  def verify_issuer_auth(%{issuer_auth: sign1}, {_x, _y} = key) do
    with :ok <- Cose.Sign1.verify_es256(sign1, <<>>, nil, key),
         {:ok, mso} <- decode_mso(sign1) do
      {:ok, mso}
    else
      {:error, reason} when reason in [:missing_cose_alg, :unexpected_cose_alg] ->
        {:error, reason}

      {:error, _} ->
        {:error, :credential_signature_invalid}
    end
  end

  @doc """
  Re-hash every disclosed item and compare against the MSO.

  This is what makes selective disclosure safe: the issuer signed a digest per
  element, so omitting elements is free but altering one is not.
  """
  @spec verify_value_digests(list(), map()) :: :ok | {:error, atom()}
  def verify_value_digests(items, mso) do
    with %{} = value_digests <- Map.get(mso, "valueDigests"),
         "SHA-256" <- Map.get(mso, "digestAlgorithm") do
      Enum.reduce_while(items, :ok, fn item, _acc ->
        case digest_for(value_digests, item) do
          {:ok, expected} ->
            if :crypto.hash(:sha256, item.raw_bytes) == expected,
              do: {:cont, :ok},
              else: {:halt, {:error, :invalid_disclosure}}

          :error ->
            {:halt, {:error, :invalid_disclosure}}
        end
      end)
    else
      _ -> {:error, :invalid_disclosure}
    end
  end

  @doc "The holder's public key, which an mdoc carries directly rather than by reference."
  @spec device_key(map()) :: {:ok, {binary(), binary()}} | {:error, atom()}
  def device_key(mso) do
    case get_in(mso, ["deviceKeyInfo", "deviceKey"]) do
      nil -> {:error, :malformed_device_key}
      key -> Cose.Key.parse_p256(key)
    end
  end

  @doc "The signed validity window, as `DateTime`s."
  @spec validity(map()) :: {:ok, map()} | {:error, atom()}
  def validity(mso) do
    with %{} = info <- Map.get(mso, "validityInfo"),
         {:ok, signed} <- to_datetime(info["signed"]),
         {:ok, valid_from} <- to_datetime(info["validFrom"]),
         {:ok, valid_until} <- to_datetime(info["validUntil"]) do
      {:ok, %{signed: signed, valid_from: valid_from, valid_until: valid_until}}
    else
      _ -> {:error, :malformed_validity_info}
    end
  end

  @doc "Disclosed elements as `%{namespace => %{element_identifier => value}}`."
  @spec elements(list()) :: %{String.t() => %{String.t() => term()}}
  def elements(items) do
    Enum.reduce(items, %{}, fn item, acc ->
      Map.update(
        acc,
        item.namespace,
        %{item.element_identifier => item.element_value},
        &Map.put(&1, item.element_identifier, item.element_value)
      )
    end)
  end

  @doc """
  Convert a decoded CBOR value into something `Jason` can encode.

  `verification_sessions.presentation_data` is a jsonb column, so a
  `%CBOR.Tag{tag: :bytes}` or a `DateTime` reaching `Repo.insert` raises inside
  the transaction that finalizes the session. This is required, not cosmetic.
  """
  @spec to_json_value(term()) :: term()
  def to_json_value(%CBOR.Tag{tag: :bytes, value: bin}) when is_binary(bin),
    do: Base.url_encode64(bin, padding: false)

  def to_json_value(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  def to_json_value(%Date{} = d), do: Date.to_iso8601(d)

  def to_json_value(%CBOR.Tag{tag: tag, value: value}) when tag in [0, 1, 1004],
    do: to_json_value(value)

  def to_json_value(%CBOR.Tag{tag: tag, value: value}),
    do: %{"tag" => tag, "value" => to_json_value(value)}

  def to_json_value(%URI{} = uri), do: URI.to_string(uri)
  def to_json_value(list) when is_list(list), do: Enum.map(list, &to_json_value/1)

  def to_json_value(map) when is_map(map) and not is_struct(map),
    do: Map.new(map, fn {k, v} -> {to_string(k), to_json_value(v)} end)

  def to_json_value(other), do: other

  # ── Internals ───────────────────────────────────────────

  defp decode_b64(b64) do
    case Base.url_decode64(b64, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> Base.decode64(b64, padding: false)
    end
  end

  defp parse_document(document) when is_map(document) do
    with doc_type when is_binary(doc_type) <- Map.get(document, "docType"),
         %{} = issuer_signed <- Map.get(document, "issuerSigned"),
         {:ok, issuer_auth} <- Cose.Sign1.parse(Map.get(issuer_signed, "issuerAuth")),
         {:ok, items} <- parse_items(Map.get(issuer_signed, "nameSpaces")),
         %{} = device_signed <- Map.get(document, "deviceSigned") do
      {:ok,
       %{
         doc_type: doc_type,
         issuer_auth: issuer_auth,
         items: items,
         device_name_spaces_bytes: Map.get(device_signed, "nameSpaces"),
         device_auth: Map.get(device_signed, "deviceAuth")
       }}
    else
      _ -> {:error, :malformed_vp_token}
    end
  end

  defp parse_document(_), do: {:error, :malformed_vp_token}

  defp parse_items(name_spaces) when is_map(name_spaces) do
    Enum.reduce_while(name_spaces, {:ok, []}, fn {namespace, tagged_items}, {:ok, acc} ->
      case parse_namespace(namespace, tagged_items) do
        {:ok, items} -> {:cont, {:ok, acc ++ items}}
        error -> {:halt, error}
      end
    end)
  end

  defp parse_items(_), do: {:error, :malformed_vp_token}

  defp parse_namespace(namespace, tagged_items)
       when is_binary(namespace) and is_list(tagged_items) do
    Enum.reduce_while(tagged_items, {:ok, []}, fn tagged, {:ok, acc} ->
      with {:ok, raw_bytes} <- Cbor.unwrap_embedded(tagged),
           {:ok, item} when is_map(item) <- Cbor.decode(raw_bytes),
           digest_id when is_integer(digest_id) <- Map.get(item, "digestID"),
           element_identifier when is_binary(element_identifier) <-
             Map.get(item, "elementIdentifier") do
        {:cont,
         {:ok,
          acc ++
            [
              %{
                namespace: namespace,
                digest_id: digest_id,
                element_identifier: element_identifier,
                element_value: Map.get(item, "elementValue"),
                raw_bytes: wrapper_bytes(raw_bytes)
              }
            ]}}
      else
        _ -> {:halt, {:error, :malformed_vp_token}}
      end
    end)
  end

  defp parse_namespace(_, _), do: {:error, :malformed_vp_token}

  # The digest covers the whole tag-24 wrapper, so that is what gets hashed.
  #
  # Rebuilt around `inner` — the payload, which the decoder hands back untouched
  # — rather than kept as received. Safe because the rebuild is *normalising*:
  # both heads come out shortest-form, the only form 18013-5 permits, so this
  # equals what a conformant issuer signed even if a transport rewrote them.
  # `Sovra.Cbor` has the long version, including why a map cannot be treated
  # this way.
  defp wrapper_bytes(inner), do: Cbor.encode(Cbor.embed_encoded(inner))

  defp digest_for(value_digests, item) do
    case get_in(value_digests, [item.namespace, item.digest_id]) do
      %CBOR.Tag{tag: :bytes, value: digest} -> {:ok, digest}
      digest when is_binary(digest) -> {:ok, digest}
      _ -> :error
    end
  end

  defp decode_mso(sign1) do
    with payload when is_binary(payload) <- sign1.payload,
         {:ok, wrapper} <- Cbor.decode(payload),
         {:ok, mso_bytes} <- Cbor.unwrap_embedded(wrapper),
         {:ok, mso} when is_map(mso) <- Cbor.decode(mso_bytes) do
      {:ok, mso}
    else
      _ -> {:error, :credential_signature_invalid}
    end
  end

  defp to_datetime(%DateTime{} = dt), do: {:ok, dt}

  defp to_datetime(%CBOR.Tag{tag: 0, value: value}) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _} -> {:ok, dt}
      _ -> :error
    end
  end

  defp to_datetime(_), do: :error
end
