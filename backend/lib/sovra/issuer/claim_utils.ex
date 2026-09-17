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
