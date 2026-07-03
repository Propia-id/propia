defmodule Sovra.Credentials.SDJWTTest do
  use ExUnit.Case, async: true

  alias Sovra.Credentials.SDJWT
  alias Sovra.Crypto.P256

  defp b64url(bin), do: Base.url_encode64(bin, case: :lower, padding: false)
  defp hex0x(bin), do: "0x" <> Base.encode16(bin, case: :lower)
  defp index_of(h, n), do: :binary.match(h, n) |> elem(0)

  # Build a KB-JWT (alg: "WebAuthn") whose holder binding is a passkey
  # assertion over sha256(signing_input), and return it with the holder key.
  defp webauthn_kb_jwt(opts \\ []) do
    {:ok, %{private_key: priv, public_key_x: x, public_key_y: y}} = P256.generate_key_pair()

    header = %{"alg" => "WebAuthn", "typ" => "kb+jwt"}
    payload = %{"aud" => "https://verifier.example", "nonce" => "n-123", "iat" => 1_700_000_000}

    signing_input =
      b64url(Jason.encode!(header)) <> "." <> b64url(Jason.encode!(payload))

    digest = :crypto.hash(:sha256, signing_input)
    challenge_b64 = Base.url_encode64(digest, padding: false)

    cdj =
      ~s({"type":"webauthn.get","challenge":") <>
        challenge_b64 <> ~s(","origin":"https://wallet.example"})

    flags = Keyword.get(opts, :flags, 0x05)
    auth_data = :crypto.strong_rand_bytes(32) <> <<flags>> <> <<0, 0, 0, 1>>
    message_hash = :crypto.hash(:sha256, auth_data <> :crypto.hash(:sha256, cdj))
    {:ok, %{r: r, s: s}} = P256.sign(message_hash, priv)

    assertion =
      Jason.encode!(%{
        "r" => hex0x(r),
        "s" => hex0x(s),
        "challenge_index" => index_of(cdj, ~s("challenge":")),
        "type_index" => index_of(cdj, ~s("type":"webauthn.get")),
        "authenticator_data" => hex0x(auth_data),
        "client_data_json" => cdj
      })

    kb_jwt = signing_input <> "." <> b64url(assertion)
    {kb_jwt, %{kty: "EC", crv: "P-256", x: x, y: y}}
  end

  describe "verify_kb_signature/2 — WebAuthn" do
    test "accepts a passkey assertion by the resolved holder key" do
      {kb_jwt, key} = webauthn_kb_jwt()

      assert {:ok, %{header: %{"alg" => "WebAuthn"}, payload: %{"nonce" => "n-123"}}} =
               SDJWT.verify_kb_signature(kb_jwt, [key])
    end

    test "rejects when the holder key doesn't match" do
      {kb_jwt, _key} = webauthn_kb_jwt()
      {:ok, %{public_key_x: ox, public_key_y: oy}} = P256.generate_key_pair()
      other = %{kty: "EC", crv: "P-256", x: ox, y: oy}

      assert {:error, :invalid_kb_signature} = SDJWT.verify_kb_signature(kb_jwt, [other])
    end

    test "rejects when the UV flag is unset" do
      {kb_jwt, key} = webauthn_kb_jwt(flags: 0x01)
      assert {:error, :invalid_kb_signature} = SDJWT.verify_kb_signature(kb_jwt, [key])
    end

    test "rejects a malformed assertion segment" do
      {kb_jwt, key} = webauthn_kb_jwt()
      [si1, si2, _sig] = String.split(kb_jwt, ".")
      broken = si1 <> "." <> si2 <> "." <> b64url("not json")
      assert {:error, :invalid_kb_signature} = SDJWT.verify_kb_signature(broken, [key])
    end
  end
end
