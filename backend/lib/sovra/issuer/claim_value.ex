defmodule Sovra.Issuer.ClaimValue do
  @moduledoc """
  Checks the claim values whose shape the holder's wallet depends on.

  A schema's `type` is advisory almost everywhere: the dashboard sends every
  value as a string, so a `number` claim arrives as `"42"` and issuing it works
  exactly as intended. Type-checking every claim would reject values that issue
  perfectly well today, which is why this inspects **only** the types that carry
  a structural contract and lets everything else through untouched.

  Today that is one type. An `attachment` is a document carried inside the
  credential as a `data:` URI, and the wallet splits it out of the credential
  before storing it — so a value that is not a bounded PDF data URI is not a
  claim the wallet can put anywhere. Discovering that at delivery time would
  surface in the middle of the holder's wallet flow, long after the operator has
  gone; checked at offer creation it is a 422 on the request that introduced it.
  Same reasoning as `Sovra.Issuer.MdocElement.encodable?/2`, and the same
  placement.
  """

  alias Sovra.Issuer.ClaimUtils

  @attachment_type "attachment"

  # Media types an attachment may carry. Widening this needs no stored data to change.
  @attachment_media_types ~w(application/pdf)

  # Cap on the whole `data:` URI, measured in bytes because the URI is what lands
  # in jsonb, in the signed JWT and in the webhook.
  #
  # 400 KB of PDF encodes to 546,164 bytes of URI. This sits just above, so the
  # console's own 400 KB limit is what an operator actually meets — the server
  # bound is the backstop for the API, not the message anyone reads.
  @max_attachment_uri_bytes 560_000

  # Anchored, lowercase media type, standard alphabet, padding allowed, no
  # whitespace. A `data:` URI may not contain whitespace, and stripping it would
  # mean revalidating the result — rejecting is the honest answer. Accepting
  # several spellings of one value is how two issuers end up disagreeing about
  # what they sent.
  #
  # `\z`, not `$`: PCRE's `$` also matches before a final newline, so `$` would
  # admit `…\n` — the exact output of `base64 -w0` — and the wallet, whose own
  # pattern does not, would keep the whole URI in its credential index.
  @data_uri ~r|^data:([a-z]+/[a-z0-9.+-]+);base64,([A-Za-z0-9+/]+={0,2})\z|

  def attachment_type, do: @attachment_type
  def attachment_media_types, do: @attachment_media_types
  def max_attachment_uri_bytes, do: @max_attachment_uri_bytes

  @doc """
  The attachment claims among a schema's claim definitions, in any shape
  `ClaimUtils.parse_claim_defs/1` reads.

  The one place that decides what counts as an attachment, for every module
  that treats one differently: validation, the offer preview, the webhook and
  the issuer metadata.
  """
  @spec attachment_claims(list() | map()) :: [map()]
  def attachment_claims(claims) do
    claims |> ClaimUtils.parse_claim_defs() |> Enum.filter(&attachment?/1)
  end

  @doc "Whether one claim definition declares an attachment."
  @spec attachment?(term()) :: boolean()
  def attachment?(%{"type" => @attachment_type}), do: true
  def attachment?(_), do: false

  @doc """
  Whether every claim the schema declares holds a value of the shape its type
  promises.

  Only `attachment` claims are inspected. A claim the caller did not send is not
  this function's problem — `ClaimUtils.validate_required_claims/2` owns
  presence.

  `nil` on an optional attachment counts as not sent: it is how a JSON client
  says "no value", and `SDJWT.split_claims/2` already drops it. On a required
  one it is still refused, because `validate_required_claims/2` only checks
  that the key is there.
  """
  @spec validate(map(), map()) :: :ok | {:error, {:invalid_claim_values, [{String.t(), atom()}]}}
  def validate(schema, claims) when is_map(claims) do
    invalid =
      schema.claims
      |> attachment_claims()
      |> Enum.flat_map(fn claim_def ->
        key = claim_def["key"]
        required = claim_def["required"] not in [nil, false]

        case Map.fetch(claims, key) do
          {:ok, nil} when not required ->
            []

          {:ok, value} ->
            case check_attachment(value) do
              :ok -> []
              {:error, reason} -> [{key, reason}]
            end

          :error ->
            []
        end
      end)

    case invalid do
      [] -> :ok
      reasons -> {:error, {:invalid_claim_values, reasons}}
    end
  end

  @doc """
  The media type and decoded size of an attachment URI.

  Used to describe an attachment where the bytes themselves must not go: the
  unsigned offer preview, and the `credential.issued` webhook.
  """
  @spec describe(term()) ::
          {:ok, %{media_type: String.t(), bytes: non_neg_integer()}} | :error
  def describe(value) when is_binary(value) do
    case Regex.run(@data_uri, value) do
      [_, media_type, payload] ->
        {:ok, %{media_type: media_type, bytes: decoded_size(payload)}}

      _ ->
        :error
    end
  end

  def describe(_), do: :error

  defp check_attachment(value) when not is_binary(value), do: {:error, :not_a_string}

  defp check_attachment(value) do
    # Size first: a rejected payload should not be run through a regex whose
    # cost scales with it.
    if byte_size(value) > @max_attachment_uri_bytes do
      {:error, :too_large}
    else
      case Regex.run(@data_uri, value) do
        [_, media_type, payload] ->
          cond do
            media_type not in @attachment_media_types ->
              {:error, :unsupported_media_type}

            # The alphabet alone admits payloads no decoder accepts: a length
            # that is not a multiple of four, or no padding where it is due.
            # The wallet would write one to disk as the holder's document.
            Base.decode64(payload) == :error ->
              {:error, :not_a_data_uri}

            true ->
              :ok
          end

        _ ->
          {:error, :not_a_data_uri}
      end
    end
  end

  # From the encoded length rather than by decoding it: the answer is exact and
  # a caller asking for a description should not pay for a 400 KB allocation.
  # Padding can only be the last two characters, so those are all it reads.
  defp decoded_size(payload) do
    padding =
      cond do
        String.ends_with?(payload, "==") -> 2
        String.ends_with?(payload, "=") -> 1
        true -> 0
      end

    div(byte_size(payload), 4) * 3 - padding
  end
end
