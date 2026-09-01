/**
 * Test fixtures: generates a complete valid SD-JWT presentation
 * with real P256 signatures for end-to-end verification testing.
 */
import { p256 } from "@noble/curves/p256";
import {
  sha256,
  base64urlEncode,
  hexToBytes,
  bytesToHex,
  concatBytes,
  keccak256,
} from "@sovrahq/holder-core/utils";

// ─── Key Generation ──────────────────────────────────

export function generateP256KeyPair() {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false); // 65 bytes uncompressed
  return {
    privateKey,
    publicKey,
    x: publicKey.slice(1, 33),
    y: publicKey.slice(33, 65),
  };
}

// ─── Signing ─────────────────────────────────────────

function signJwt(signingInput: string, privateKey: Uint8Array): string {
  const hash = sha256(new TextEncoder().encode(signingInput));
  const sig = p256.sign(hash, privateKey, { lowS: true });
  const r = hexToBytes(sig.r.toString(16).padStart(64, "0"));
  const s = hexToBytes(sig.s.toString(16).padStart(64, "0"));
  return base64urlEncode(concatBytes(r, s));
}

/**
 * Build a WebAuthn (passkey) KB-JWT that mirrors the Sovra wallet's wire format:
 * a JWT whose third segment is base64url(JSON) of a WebAuthn assertion. The
 * passkey signs `authenticatorData || SHA256(clientDataJSON)`, and
 * clientDataJSON embeds `challenge = base64url(SHA256(kbSigningInput))`.
 *
 * `overrides.challenge` and `overrides.flags` allow constructing invalid
 * assertions (tampered challenge / missing UV) for negative tests.
 */
function buildWebAuthnKbJwt(
  passkey: ReturnType<typeof generateP256KeyPair>,
  kbSigningInput: string,
  overrides: { challenge?: string; flags?: number } = {},
): string {
  const realChallenge = base64urlEncode(
    sha256(new TextEncoder().encode(kbSigningInput)),
  );
  const challenge = overrides.challenge ?? realChallenge;

  // clientDataJSON with `type` and `challenge` in the canonical leading order.
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://sovra.example","crossOrigin":false}`;
  const challengeIndex = clientDataJSON.indexOf('"challenge":');
  const typeIndex = clientDataJSON.indexOf('"type":');

  // authenticatorData = rpIdHash(32) || flags(1) || signCount(4). rpIdHash and
  // signCount are not checked by the verifier; flags default to UP|UV set.
  const rpIdHash = sha256(new TextEncoder().encode("sovra.example"));
  const flags = overrides.flags ?? 0x05; // UP (0x01) | UV (0x04)
  const authData = concatBytes(
    rpIdHash,
    new Uint8Array([flags]),
    new Uint8Array([0, 0, 0, 1]),
  );

  const clientDataHash = sha256(new TextEncoder().encode(clientDataJSON));
  const messageHash = sha256(concatBytes(authData, clientDataHash));
  const sig = p256.sign(messageHash, passkey.privateKey, { lowS: true });
  const r = hexToBytes(sig.r.toString(16).padStart(64, "0"));
  const s = hexToBytes(sig.s.toString(16).padStart(64, "0"));

  const segment = {
    r: bytesToHex(r), // 0x-prefixed
    s: bytesToHex(s),
    challenge_index: challengeIndex,
    type_index: typeIndex,
    authenticator_data: bytesToHex(authData),
    client_data_json: clientDataJSON,
  };
  const segB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(segment)),
  );
  return `${kbSigningInput}.${segB64}`;
}

// ─── Build Complete Presentation ─────────────────────

export interface FixtureKeys {
  issuer: ReturnType<typeof generateP256KeyPair>;
  passkey: ReturnType<typeof generateP256KeyPair>;
  recovery: ReturnType<typeof generateP256KeyPair>;
}

export interface FixtureOptions {
  issuerAddress?: string;
  holderAddress?: string;
  vct?: string;
  claims?: Record<string, unknown>;
  disclosableClaims?: Record<string, unknown>;
  exp?: number;
  /** Omit `exp` entirely — SD-JWT VC makes it OPTIONAL. */
  noExp?: boolean;
  iat?: number;
  nonce?: string;
  audience?: string;
  sub?: string | null;
  /** Override raw issuer payload fields (merged after construction) */
  rawPayloadOverrides?: Record<string, unknown>;
  /** KB-JWT holder-proof algorithm. Defaults to raw ES256. */
  kbAlg?: "ES256" | "WebAuthn";
  /** For kbAlg "WebAuthn": tamper with the assertion for negative tests. */
  webauthnOverrides?: { challenge?: string; flags?: number };
}

export function generateKeys(): FixtureKeys {
  return {
    issuer: generateP256KeyPair(),
    passkey: generateP256KeyPair(),
    recovery: generateP256KeyPair(),
  };
}

export function buildPresentation(
  keys: FixtureKeys,
  opts: FixtureOptions = {},
) {
  const issuerAddress = opts.issuerAddress ?? "0x1234567890abcdef1234567890abcdef12345678";
  const holderAddress = opts.holderAddress ?? "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
  const vct = opts.vct ?? "DrivingLicenceCredential";
  const nonce = opts.nonce ?? "test-nonce-123";
  const audience = opts.audience ?? "did:sovra:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const now = Math.floor(Date.now() / 1000);
  const iat = opts.iat ?? now;
  const exp = opts.exp ?? now + 86400; // 24 hours from now

  const nonDisclosableClaims = opts.claims ?? { iss_country: "EX" };
  const disclosableClaims = opts.disclosableClaims ?? {
    given_name: "Maria",
    family_name: "Rossi",
    birth_date: "1990-07-15",
  };

  // Build disclosures
  const disclosures: Array<{ encoded: string; salt: string; key: string; value: unknown }> = [];
  const sdDigests: string[] = [];

  for (const [key, value] of Object.entries(disclosableClaims)) {
    const salt = bytesToHex(
      crypto.getRandomValues(new Uint8Array(16)),
      false,
    );
    const disclosureArray = [salt, key, value];
    const encoded = base64urlEncode(
      new TextEncoder().encode(JSON.stringify(disclosureArray)),
    );
    const digest = base64urlEncode(sha256(new TextEncoder().encode(encoded)));
    disclosures.push({ encoded, salt, key, value });
    sdDigests.push(digest);
  }

  // Build issuer JWT
  const issuerHeader = { alg: "ES256", typ: "vc+sd-jwt" };
  const issuerPayload: Record<string, unknown> = {
    iss: `did:sovra:${issuerAddress}`,
    ...(opts.sub !== null && { sub: opts.sub ?? `did:sovra:${holderAddress}` }),
    vct,
    cnf: { kid: `did:sovra:${holderAddress}#passkey` },
    iat,
    ...(opts.noExp ? {} : { exp }),
    _sd: sdDigests,
    _sd_alg: "sha-256",
    ...nonDisclosableClaims,
    ...opts.rawPayloadOverrides,
  };

  const headerB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(issuerHeader)),
  );
  const payloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(issuerPayload)),
  );
  const issuerSigningInput = `${headerB64}.${payloadB64}`;
  const issuerSig = signJwt(issuerSigningInput, keys.issuer.privateKey);
  const issuerJwt = `${issuerSigningInput}.${issuerSig}`;

  // Build KB-JWT
  const disclosurePart = disclosures.map((d) => d.encoded).join("~");
  const hashInput = `${issuerJwt}~${disclosurePart}~`;
  const sdHash = base64urlEncode(sha256(new TextEncoder().encode(hashInput)));

  const kbAlg = opts.kbAlg ?? "ES256";
  const kbHeader =
    kbAlg === "WebAuthn"
      ? {
          alg: "WebAuthn",
          typ: "kb+jwt",
          // Holder-self-asserted JWK — verifier ignores it and uses on-chain keys.
          jwk: {
            kty: "EC",
            crv: "P-256",
            x: base64urlEncode(keys.passkey.x),
            y: base64urlEncode(keys.passkey.y),
          },
        }
      : { alg: "ES256", typ: "kb+jwt" };
  const kbPayload = {
    iat: now,
    nonce,
    aud: audience,
    sd_hash: sdHash,
  };

  const kbHeaderB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(kbHeader)),
  );
  const kbPayloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(kbPayload)),
  );
  const kbSigningInput = `${kbHeaderB64}.${kbPayloadB64}`;

  const kbJwt =
    kbAlg === "WebAuthn"
      ? buildWebAuthnKbJwt(keys.passkey, kbSigningInput, opts.webauthnOverrides)
      : // Passkey-only 64-byte ES256 signature
        `${kbSigningInput}.${signJwt(kbSigningInput, keys.passkey.privateKey)}`;

  // Assemble full presentation
  const presentation = `${issuerJwt}~${disclosurePart}~${kbJwt}`;

  return {
    presentation,
    issuerJwt,
    kbJwt,
    disclosures,
    issuerAddress,
    holderAddress,
    vct,
    nonce,
    audience,
    exp,
    iat,
    sdHash,
    credentialTypeId: bytesToHex(keccak256(new TextEncoder().encode(vct)), false),
  };
}
