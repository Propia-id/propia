defmodule Sovra.Mdoc.SessionTranscriptTest do
  use ExUnit.Case, async: true

  alias Sovra.Cbor
  alias Sovra.Mdoc.SessionTranscript
  alias Sovra.Verification.RequestObject

  # These exact strings are also in
  # frontend/packages/holder-core/test/session-transcript.test.ts, which asserts
  # the same hex. The wallet and the verifier build this independently and never
  # exchange it, so the vectors are the only thing keeping them in agreement.
  #
  # A diff here is a protocol change: every mdoc presentation from a wallet on
  # the old profile stops verifying. Wallets ship through app stores and cannot
  # be force-updated, so a change means the verifier accepts both for a while.
  @client_id "verifier:018f4a1c-0000-7000-8000-000000000001"
  @nonce "n-0S6_WzA2Mj"
  @response_uri "https://api.sovra.io/wallet/verifier/direct_post/018f4a1c-0000-7000-8000-000000000002"

  # 32 bytes standing in for an RFC 7638 SHA-256 thumbprint. Only reachable once
  # we adopt `direct_post.jwt`; pinned now so that switch is a config change and
  # not a debugging session.
  @jwk_thumbprint Base.decode16!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    case: :lower
                  )

  defp hex(bin), do: Base.encode16(bin, case: :lower)

  describe "interop vector" do
    test "handover info encodes to the pinned bytes" do
      encoded =
        SessionTranscript.handover_info(@client_id, @nonce, @response_uri)
        |> Cbor.encode()

      assert hex(encoded) ==
               "84782d76657269666965723a30313866346131632d303030302d373030302d383030302d3030303030303030303030316c6e2d3053365f577a41324d6af6785568747470733a2f2f6170692e736f7672612e696f2f77616c6c65742f76657269666965722f6469726563745f706f73742f30313866346131632d303030302d373030302d383030302d303030303030303030303032"
    end

    test "the handover hash is stable" do
      # The single value both implementations must agree on.
      hash =
        :crypto.hash(
          :sha256,
          Cbor.encode(SessionTranscript.handover_info(@client_id, @nonce, @response_uri))
        )

      assert hex(hash) == "25630aac8da3e1af259fafd965aad44fd56ca8c5242d450bddcdf9f939cc131d"
    end

    test "the transcript encodes to the pinned bytes" do
      encoded = SessionTranscript.from_parts(@client_id, @nonce, @response_uri) |> Cbor.encode()

      assert hex(encoded) ==
               "83f6f682714f70656e494434565048616e646f766572582025630aac8da3e1af259fafd965aad44fd56ca8c5242d450bddcdf9f939cc131d"
    end

    test "a present thumbprint travels as a byte string" do
      encoded =
        SessionTranscript.handover_info(@client_id, @nonce, @response_uri, @jwk_thumbprint)
        |> Cbor.encode()

      # OpenID4VP 1.0 §B.2.6 requires it "encoded as a Byte String", so it sits
      # under a `5820` head — bstr of 32 — and not `7820`, which is what a
      # base64url *string* of the same digest would produce. That would hash to
      # something no conformant verifier rebuilds.
      assert hex(encoded) =~ "5820" <> hex(@jwk_thumbprint)

      assert hex(encoded) ==
               "84782d76657269666965723a30313866346131632d303030302d373030302d383030302d3030303030303030303030316c6e2d3053365f577a41324d6a5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f785568747470733a2f2f6170692e736f7672612e696f2f77616c6c65742f76657269666965722f6469726563745f706f73742f30313866346131632d303030302d373030302d383030302d303030303030303030303032"
    end

    test "the encrypted-response transcript encodes to the pinned bytes" do
      encoded =
        SessionTranscript.from_parts(@client_id, @nonce, @response_uri, @jwk_thumbprint)
        |> Cbor.encode()

      assert hex(encoded) ==
               "83f6f682714f70656e494434565048616e646f7665725820d6514d1f40d8508de2578eaa4b905cc44c203df89a8af860ecab249247a3b939"
    end
  end

  describe "structure" do
    test "is [null, null, [\"OpenID4VPHandover\", hash]]" do
      assert [nil, nil, ["OpenID4VPHandover", %CBOR.Tag{tag: :bytes, value: hash}]] =
               SessionTranscript.from_parts(@client_id, @nonce, @response_uri)

      assert byte_size(hash) == 32
    end

    test "every input changes the hash" do
      base = SessionTranscript.from_parts(@client_id, @nonce, @response_uri)

      refute base == SessionTranscript.from_parts("verifier:other", @nonce, @response_uri)
      refute base == SessionTranscript.from_parts(@client_id, "other-nonce", @response_uri)
      refute base == SessionTranscript.from_parts(@client_id, @nonce, "https://elsewhere/post")

      # A presentation must not be replayable to a verifier that asked for it
      # with a different response address.
      refute base ==
               SessionTranscript.from_parts(@client_id, @nonce, @response_uri, @jwk_thumbprint)
    end
  end

  describe "build/1" do
    test "takes the client_id off the session rather than rebuilding it" do
      # Takes only the session so the verifier's workspace cannot be confused
      # with the issuer's — a mix-up that produces a transcript no wallet can
      # match, and a signature error pointing nowhere near the cause.
      #
      # The stored `client_id` is the exact string signed into the request
      # object and sent to the wallet. The transcript has to hash what was
      # sent, so it is read back rather than derived a second time.
      session = %Sovra.Verification.Session{
        id: "018f4a1c-0000-7000-8000-000000000002",
        workspace_id: "018f4a1c-0000-7000-8000-000000000001",
        client_id: @client_id,
        nonce: @nonce
      }

      assert SessionTranscript.build(session) ==
               SessionTranscript.from_parts(
                 @client_id,
                 session.nonce,
                 RequestObject.response_uri(session)
               )
    end
  end
end
