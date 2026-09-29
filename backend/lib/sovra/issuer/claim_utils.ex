defmodule Sovra.Issuer.ClaimUtils do
  @moduledoc """
  Shared utility functions for the issuer domain.
  """

  @doc """
  Parse claim definitions from a schema's claims field.
  Handles both list format and `%{"claims" => [...]}` map format.
  """
  def parse_claim_defs(claims) when is_list(claims), do: claims

  def parse_claim_defs(claims) when is_map(claims) do
    case Map.get(claims, "claims") do
      list when is_list(list) -> list
      _ -> []
    end
  end

  @doc """
  Verifies that every claim marked `required` in the schema is present.

  Shared by both issuance paths: credential offers (wallet) and signed
  documents (no wallet).
  """
  def validate_required_claims(schema, claims) do
    required_keys =
      schema.claims
      |> parse_claim_defs()
      |> Enum.filter(& &1["required"])
      |> Enum.map(& &1["key"])

    case Enum.reject(required_keys, &Map.has_key?(claims, &1)) do
      [] -> :ok
      missing -> {:error, {:missing_claims, missing}}
    end
  end

  @doc """
  Keeps only the claim values the schema declares, in the schema's own order.
  Anything the caller sends that the schema doesn't define is dropped.
  """
  def take_declared_claims(schema, claims) do
    schema.claims
    |> parse_claim_defs()
    |> Enum.flat_map(fn def ->
      key = def["key"]

      case Map.fetch(claims, key) do
        {:ok, value} -> [{key, value}]
        :error -> []
      end
    end)
    |> Map.new()
  end

  @doc """
  Parses a schema validity period (`"1y"`, `"6m"`, `"30d"`) into seconds.

  `nil` in, `nil` out: no validity period, so no expiry at all. An unparseable
  string still falls back to one year.

  Shared by every issuance path — SD-JWT, mdoc, and signed documents — so all
  three derive expiry the same way.
  """
  def parse_validity_period(nil), do: nil

  def parse_validity_period(period) do
    case Regex.run(~r/^(\d+)(y|m|d)$/, period) do
      [_, n, "y"] -> String.to_integer(n) * 365 * 86400
      [_, n, "m"] -> String.to_integer(n) * 30 * 86400
      [_, n, "d"] -> String.to_integer(n) * 86400
      _ -> 365 * 86400
    end
  end

  @doc """
  The instant a credential built with `opts` expires, or `nil` for no expiry.

  The single place expiry is decided, for every issuance path — SD-JWT, mdoc,
  signed documents, and the offer preview. Each one calls this rather than
  deriving its own, so the signed `exp` (or `ValidityInfo.validUntil`), the
  `issued_credentials` row and the preview cannot disagree. They used to be
  three separate computations that agreed only because `deliver_credential/3`
  threaded the same `now:` into each, and that the preview did not share at all.

  Options:

    * `:valid_until` — an issuer's explicit override, already parsed by
      `parse_valid_until/1`. Beats the schema's period; that is its purpose.
    * `:now` — pins the instant a relative period is measured from. Callers
      that need the result to match a timestamp they record elsewhere must pass
      it, or two clock reads can land on either side of a second boundary.

  `nil` out means the schema declares no validity period and no override was
  given, so SD-JWT omits `exp` entirely. mdoc cannot express that —
  `ValidityInfo.validUntil` is mandatory — and supplies its own fallback.
  """
  @spec resolve_expiry(map(), keyword()) :: DateTime.t() | nil
  def resolve_expiry(schema, opts \\ []) do
    case Keyword.get(opts, :valid_until) do
      %DateTime{} = valid_until ->
        DateTime.truncate(valid_until, :second)

      nil ->
        case parse_validity_period(schema.validity_period) do
          nil ->
            nil

          seconds ->
            now = Keyword.get(opts, :now) || DateTime.utc_now() |> DateTime.truncate(:second)
            DateTime.add(now, seconds, :second)
        end
    end
  end

  @doc """
  Parses an issuer-supplied `valid_until` into the instant a credential expires.

  The override for `parse_validity_period/1`: a schema's period says "a year
  from whenever this is redeemed", which cannot express "expire exactly when the
  credential I am replacing did". Re-issuance needs the absolute date.

  Strict on purpose — this is a write boundary, and every rejected shape here
  would otherwise become a signed expiry nobody chose:

    * only a string is accepted, so `null` is a 422 rather than a second
      spelling of "use the schema default". Omitting the field is the one way
      to ask for the default.
    * the instant must be in the future, or the credential is expired the
      moment it is signed.

  Offsets are honoured and normalised to UTC, so `"2030-03-01T00:00:00-03:00"`
  means the instant it names.
  """
  def parse_valid_until(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} ->
        datetime = datetime |> DateTime.shift_zone!("Etc/UTC") |> DateTime.truncate(:second)

        if DateTime.after?(datetime, DateTime.utc_now()) do
          {:ok, datetime}
        else
          {:error, "must be in the future"}
        end

      {:error, _reason} ->
        {:error, ~s(must be an ISO 8601 date-time like "2030-03-01T00:00:00Z")}
    end
  end

  def parse_valid_until(_value),
    do: {:error, ~s(must be an ISO 8601 date-time like "2030-03-01T00:00:00Z")}

  @doc """
  The W3C Bitstring Status List entries for an issued credential.

  Shared by the SD-JWT payload and the mdoc offer preview so the two describe
  revocation identically. The mdoc credential itself cannot use this shape —
  it has no `credentialStatus` field — and carries the index in
  `Sovra.Mdoc.MetaNamespace` instead.
  """
  def credential_status_entries(issuer, index) do
    base = "#{base_url()}/api/v1/status/#{issuer.did}"

    [
      %{
        "type" => "BitstringStatusListEntry",
        "statusPurpose" => "revocation",
        "statusListIndex" => to_string(index),
        "statusListCredential" => "#{base}/revocation"
      },
      %{
        "type" => "BitstringStatusListEntry",
        "statusPurpose" => "suspension",
        "statusListIndex" => to_string(index),
        "statusListCredential" => "#{base}/suspension"
      }
    ]
  end

  @doc """
  Returns the issuer service base URL from application config.
  """
  def base_url do
    Application.get_env(:sovra, :issuer, []) |> Keyword.get(:base_url, "http://localhost:4000")
  end
end
