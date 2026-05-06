defmodule Sovra.Issuer.OAuthMetadata do
  @moduledoc """
  RFC 8414 OAuth 2.0 Authorization Server Metadata, scoped per workspace.
  Advertises only the grant types and endpoints actually implemented today
  (pre-authorized_code via the integrated AS).
  """

  alias Sovra.Issuer.ClaimUtils

  def build_metadata(%{did: workspace_did}) when is_binary(workspace_did) do
    base_url = ClaimUtils.base_url()
    issuer = "#{base_url}/#{workspace_did}"

    %{
      "issuer" => issuer,
      "token_endpoint" => "#{base_url}/api/v1/issuer/token",
      "token_endpoint_auth_methods_supported" => ["none"],
      "grant_types_supported" => [
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ],
      "pre-authorized_grant_anonymous_access_supported" => true
    }
  end
end
