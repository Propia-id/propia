defmodule Sovra.Crypto.WebAuthnTest do
  use ExUnit.Case, async: true

  alias Sovra.Crypto.{P256, WebAuthn}

  # Builds a valid WebAuthn assertion over `digest` signed by `priv`, plus the
  # matching public key coordinates.
  defp assertion_for(digest, opts \\ []) do
    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

    flags = Keyword.get(opts, :flags, 0x05)
    challenge_b64 = Base.url_encode64(digest, padding: false)

    cdj =
      ~s({"type":"webauthn.get","challenge":") <>
        challenge_b64 <> ~s(","origin":"https://wallet.example"})

    # rpIdHash(32) || flags(1) || counter(4)
    auth_data = :crypto.strong_rand_bytes(32) <> <<flags>> <> <<0, 0, 0, 1>>

    message_hash = :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, cdj))
    {:ok, %{r: r, s: s}} = P256.sign(message_hash, priv)

    sig = %{
      r: r,
      s: s,
      challenge_index: index_of(cdj, ~s("challenge":")),
      type_index: index_of(cdj, ~s("type":"webauthn.get")),
      authenticator_data: auth_data,
      client_data_json: cdj
    }

    {sig, {x, y}}
  end

  defp index_of(haystack, needle) do
    {pos, _len} = :binary.match(haystack, needle)
    pos
  end

  describe "valid?/3" do
    test "accepts a well-formed assertion by the matching key" do
      digest = :crypto.hash(:sha256, "kb-jwt signing input")
      {sig, key} = assertion_for(digest)

      assert WebAuthn.valid?(digest, sig, key)
    end

    test "rejects a different digest (challenge mismatch)" do
      digest = :crypto.hash(:sha256, "one")
      {sig, key} = assertion_for(digest)

      refute WebAuthn.valid?(:crypto.hash(:sha256, "two"), sig, key)
    end

    test "rejects a different key" do
      digest = :crypto.hash(:sha256, "input")
      {sig, _key} = assertion_for(digest)
      {:ok, %{public_key_x: ox, public_key_y: oy}} = P256.generate_key_pair()

      refute WebAuthn.valid?(digest, sig, {ox, oy})
    end

    test "rejects when the user-verified (UV) flag is unset" do
      digest = :crypto.hash(:sha256, "input")
      # 0x01 = UP only, no UV.
      {sig, key} = assertion_for(digest, flags: 0x01)

      refute WebAuthn.valid?(digest, sig, key)
    end

    test "rejects a tampered client_data_json (signature breaks)" do
      digest = :crypto.hash(:sha256, "input")
      {sig, key} = assertion_for(digest)
      tampered = %{sig | client_data_json: sig.client_data_json <> " "}

      refute WebAuthn.valid?(digest, tampered, key)
    end

    test "rejects too-short authenticator data" do
      digest = :crypto.hash(:sha256, "input")
      {sig, key} = assertion_for(digest)
      refute WebAuthn.valid?(digest, %{sig | authenticator_data: <<0, 1, 2>>}, key)
    end

    test "rejects malformed input shapes" do
      refute WebAuthn.valid?(<<0::256>>, %{}, {<<0::256>>, <<0::256>>})
      refute WebAuthn.valid?("short", %{}, {<<0::256>>, <<0::256>>})
    end
  end
end
