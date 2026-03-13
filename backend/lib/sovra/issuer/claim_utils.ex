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
  Returns the issuer service base URL from application config.
  """
  def base_url do
    Application.get_env(:sovra, :issuer, []) |> Keyword.get(:base_url, "http://localhost:4000")
  end
end
