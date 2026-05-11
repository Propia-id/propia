defmodule SovraWeb.OpenApiSplitTest do
  @moduledoc """
  Smoke tests for the three audience-specific OpenAPI documents. Each spec
  must contain only paths beginning with its dedicated prefix.
  """
  use ExUnit.Case, async: true

  test "dashboard spec contains only /dashboard/* paths" do
    paths = SovraWeb.DashboardApiSpec.spec().paths
    refute paths == %{}, "expected at least one dashboard path"

    for {path, _item} <- paths do
      assert String.starts_with?(path, "/dashboard/"),
             "expected #{path} to start with /dashboard/"
    end
  end

  test "wallet spec contains only /wallet/* paths" do
    paths = SovraWeb.WalletApiSpec.spec().paths
    refute paths == %{}, "expected at least one wallet path"

    for {path, _item} <- paths do
      assert String.starts_with?(path, "/wallet/"),
             "expected #{path} to start with /wallet/"
    end
  end

  test "integrator spec contains only /api/v1/* paths" do
    paths = SovraWeb.ApiSpec.spec().paths
    refute paths == %{}, "expected at least one integrator path"

    for {path, _item} <- paths do
      assert String.starts_with?(path, "/api/v1/"),
             "expected #{path} to start with /api/v1/"
    end
  end
end
