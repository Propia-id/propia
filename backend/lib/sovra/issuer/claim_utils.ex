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
  Returns the issuer service base URL from application config.
  """
  def base_url do
    Application.get_env(:sovra, :issuer, []) |> Keyword.get(:base_url, "http://localhost:4000")
  end
end
