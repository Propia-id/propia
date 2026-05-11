defmodule SovraWeb.OpenApiHelpers do
  @moduledoc """
  Helpers shared by the per-audience OpenAPI spec modules
  (`SovraWeb.DashboardApiSpec`, `SovraWeb.WalletApiSpec`, `SovraWeb.ApiSpec`).
  """

  alias OpenApiSpex.Paths

  @doc """
  Returns the subset of router paths whose keys start with `prefix`.
  """
  @spec paths_with_prefix(module(), String.t()) :: %{String.t() => OpenApiSpex.PathItem.t()}
  def paths_with_prefix(router, prefix) when is_atom(router) and is_binary(prefix) do
    router
    |> Paths.from_router()
    |> Enum.filter(fn {path, _item} -> String.starts_with?(path, prefix) end)
    |> Map.new()
  end
end
