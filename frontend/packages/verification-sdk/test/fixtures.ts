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
} from "@sovra/wallet-core/utils";

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

// ─── Build Complete Presentation ─────────────────────

export interface FixtureKeys {
  issuer: ReturnType<typeof generateP256KeyPair>;
  passkey: ReturnType<typeof generateP256KeyPair>;
  server: ReturnType<typeof generateP256KeyPair>;
}

export interface FixtureOptions {
  issuerAddress?: string;
  holderAddress?: string;
  vct?: string;
  claims?: Record<string, unknown>;
  disclosableClaims?: Record<string, unknown>;
  exp?: number;
  nonce?: string;
  audience?: string;
}

export function generateKeys(): FixtureKeys {
  return {
    issuer: generateP256KeyPair(),
    passkey: generateP256KeyPair(),
    server: generateP256KeyPair(),
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
  const issuerPayload = {
    iss: `did:sovra:${issuerAddress}`,
    sub: `did:sovra:${holderAddress}`,
    vct,
    cnf: { kid: `did:sovra:${holderAddress}#2of2` },
    iat: now,
    exp,
    _sd: sdDigests,
    _sd_alg: "sha-256",
    ...nonDisclosableClaims,
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

  const kbHeader = { alg: "ES256", typ: "kb+jwt" };
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

  // Compound signature: passkey (64 bytes) || server (64 bytes)
  const kbHash = sha256(new TextEncoder().encode(kbSigningInput));

  const passkeySig = p256.sign(kbHash, keys.passkey.privateKey, { lowS: true });
  const passkeyR = hexToBytes(passkeySig.r.toString(16).padStart(64, "0"));
  const passkeyS = hexToBytes(passkeySig.s.toString(16).padStart(64, "0"));

  const serverSig = p256.sign(kbHash, keys.server.privateKey, { lowS: true });
  const serverR = hexToBytes(serverSig.r.toString(16).padStart(64, "0"));
  const serverS = hexToBytes(serverSig.s.toString(16).padStart(64, "0"));

  const compoundSig = concatBytes(passkeyR, passkeyS, serverR, serverS);
  const kbSigB64 = base64urlEncode(compoundSig);
  const kbJwt = `${kbSigningInput}.${kbSigB64}`;

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
    iat: now,
    sdHash,
    credentialTypeId: bytesToHex(keccak256(new TextEncoder().encode(vct)), false),
  };
}
