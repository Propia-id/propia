import { describe, expect, it } from "vitest";
import { encode } from "../src/cbor/index";
import {
  openId4VpHandoverInfo,
  sessionTranscript,
  SESSION_TRANSCRIPT_PROFILE,
} from "../src/mdoc/index";
import { sha256 } from "../src/utils/index";

const hex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// These exact strings and expectations are duplicated in
// backend/test/sovra/mdoc/session_transcript_test.exs. That duplication is the
// point: the wallet and the verifier build the transcript independently and
// never exchange it, so a byte of disagreement makes every device signature
// verify against nothing, with no error that points at the cause.
//
// A diff to these vectors is a protocol change. Wallets ship through app stores
// and cannot be force-updated, so the verifier has to accept both profiles
// across a transition window.
const CLIENT_ID = "verifier:018f4a1c-0000-7000-8000-000000000001";
const NONCE = "n-0S6_WzA2Mj";
const RESPONSE_URI =
  "https://api.sovra.io/wallet/verifier/direct_post/018f4a1c-0000-7000-8000-000000000002";

const HANDOVER_INFO_HEX =
  "84782d76657269666965723a30313866346131632d303030302d373030302d383030302d3030" +
  "303030303030303030316c6e2d3053365f577a41324d6af6785568747470733a2f2f6170692e" +
  "736f7672612e696f2f77616c6c65742f76657269666965722f6469726563745f706f73742f30" +
  "313866346131632d303030302d373030302d383030302d303030303030303030303032";

const HANDOVER_HASH_HEX =
  "25630aac8da3e1af259fafd965aad44fd56ca8c5242d450bddcdf9f939cc131d";

const TRANSCRIPT_HEX =
  "83f6f682714f70656e494434565048616e646f7665725820" + HANDOVER_HASH_HEX;

// 32 bytes standing in for an RFC 7638 SHA-256 thumbprint. Only reachable once
// we adopt `direct_post.jwt`; pinned now so that switch is a config change and
// not a debugging session.
const JWK_THUMBPRINT = Uint8Array.from({ length: 32 }, (_, i) => i);

const THUMBPRINT_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const ENCRYPTED_INFO_HEX =
  "84782d76657269666965723a30313866346131632d303030302d373030302d383030302d3030" +
  "303030303030303030316c6e2d3053365f577a41324d6a5820" +
  THUMBPRINT_HEX +
  "785568747470733a2f2f6170692e736f7672612e696f2f77616c6c65742f76657269666965" +
  "722f6469726563745f706f73742f30313866346131632d303030302d373030302d38303030" +
  "2d303030303030303030303032";

const ENCRYPTED_HASH_HEX =
  "d6514d1f40d8508de2578eaa4b905cc44c203df89a8af860ecab249247a3b939";

const input = { clientId: CLIENT_ID, nonce: NONCE, responseUri: RESPONSE_URI };

describe("interop vector — must match Sovra.Mdoc.SessionTranscript", () => {
  it("encodes the handover info to the pinned bytes", () => {
    expect(hex(encode(openId4VpHandoverInfo(input)))).toBe(HANDOVER_INFO_HEX);
  });

  it("produces the pinned handover hash", () => {
    expect(hex(sha256(encode(openId4VpHandoverInfo(input))))).toBe(HANDOVER_HASH_HEX);
  });

  it("encodes the transcript to the pinned bytes", () => {
    expect(hex(encode(sessionTranscript(input)))).toBe(TRANSCRIPT_HEX);
  });

  it("declares the profile these vectors belong to", () => {
    expect(SESSION_TRANSCRIPT_PROFILE).toBe("openid4vp-1.0");
  });

  it("encodes a present thumbprint as a byte string", () => {
    // OpenID4VP 1.0 §B.2.6 requires it "encoded as a Byte String", so it sits
    // under a `5820` head — bstr of 32 — and not `7820`, which is what a
    // base64url *string* of the same digest would produce. That would hash to
    // something no conformant verifier rebuilds.
    const encoded = hex(encode(openId4VpHandoverInfo({ ...input, jwkThumbprint: JWK_THUMBPRINT })));

    expect(encoded).toContain(`5820${THUMBPRINT_HEX}`);
    expect(encoded).toBe(ENCRYPTED_INFO_HEX);
  });

  it("encodes the encrypted-response transcript to the pinned bytes", () => {
    expect(hex(encode(sessionTranscript({ ...input, jwkThumbprint: JWK_THUMBPRINT })))).toBe(
      "83f6f682714f70656e494434565048616e646f7665725820" + ENCRYPTED_HASH_HEX,
    );
  });
});

describe("binding", () => {
  it("is [null, null, [\"OpenID4VPHandover\", hash]]", () => {
    const transcript = sessionTranscript(input) as unknown[];
    expect(transcript[0]).toBeNull();
    expect(transcript[1]).toBeNull();

    const handover = transcript[2] as [string, Uint8Array];
    expect(handover[0]).toBe("OpenID4VPHandover");
    expect(handover[1]).toHaveLength(32);
  });

  it("changes with every input", () => {
    // Each of these is a replay the transcript has to prevent: the same
    // presentation offered to a different verifier, against a stale nonce, or
    // posted somewhere other than where it was asked for.
    const base = hex(encode(sessionTranscript(input)));

    expect(hex(encode(sessionTranscript({ ...input, clientId: "verifier:other" })))).not.toBe(base);
    expect(hex(encode(sessionTranscript({ ...input, nonce: "stale" })))).not.toBe(base);
    expect(
      hex(encode(sessionTranscript({ ...input, responseUri: "https://elsewhere/post" }))),
    ).not.toBe(base);
    expect(
      hex(encode(sessionTranscript({ ...input, jwkThumbprint: JWK_THUMBPRINT }))),
    ).not.toBe(base);
  });

  it("treats an absent thumbprint and an explicit null identically", () => {
    // `direct_post` is unencrypted, so there is no response-encryption key. The
    // two spellings must not fork the transcript.
    expect(hex(encode(sessionTranscript({ ...input, jwkThumbprint: null })))).toBe(
      hex(encode(sessionTranscript(input))),
    );
  });
});
