defmodule Sovra.Issuer.OAuthMetadataTest do
  use ExUnit.Case, async: true

  alias Sovra.Issuer.OAuthMetadata

  setup do
    prev = Application.get_env(:sovra, :issuer)
    Application.put_env(:sovra, :issuer, base_url: "https://sovra.example")
    on_exit(fn -> Application.put_env(:sovra, :issuer, prev || []) end)
    :ok
  end

  test "issuer is the workspace-scoped HTTPS identifier" do
    metadata = OAuthMetadata.build_metadata(%{did: "did:sovra:0xabc"})

    assert metadata["issuer"] == "https://sovra.example/did:sovra:0xabc"
  end

  test "advertises only the pre-authorized_code grant" do
    metadata = OAuthMetadata.build_metadata(%{did: "did:sovra:0xabc"})

    assert metadata["grant_types_supported"] == [
             "urn:ietf:params:oauth:grant-type:pre-authorized_code"
           ]
  end

  test "exposes the shared token endpoint and anonymous pre-authorized access flag" do
    metadata = OAuthMetadata.build_metadata(%{did: "did:sovra:0xabc"})

    assert metadata["token_endpoint"] == "https://sovra.example/wallet/issuer/token"
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    assert metadata["pre-authorized_grant_anonymous_access_supported"] == true
  end

  test "does not advertise unimplemented endpoints (authorization, PAR, code challenge)" do
    metadata = OAuthMetadata.build_metadata(%{did: "did:sovra:0xabc"})

    refute Map.has_key?(metadata, "authorization_endpoint")
    refute Map.has_key?(metadata, "pushed_authorization_request_endpoint")
    refute Map.has_key?(metadata, "code_challenge_methods_supported")
  end
end
