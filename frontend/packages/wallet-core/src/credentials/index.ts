import { decodeSdJwt, getClaims } from "@sd-jwt/decode";
import type { SecureStorage } from "../platform/index";
import type { StoredCredential, CredentialStore } from "../state/index";
import { sha256, base64urlDecode, base64urlEncode } from "../utils/index";

// ─── Types ────────────────────────────────────────────

export interface ParsedCredential {
  issuerJwt: string;
  disclosures: Array<{
    encoded: string;
    key: string;
    value: unknown;
    salt: string;
  }>;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  claims: Record<string, unknown>;
}

export interface IssuerInfo {
  issuerDid: string;
  issuerName: string;
}

// ─── Credential Manager ──────────────────────────────

const CREDENTIAL_PREFIX = "sovra.credential.";

export class CredentialManager {
  constructor(
    private storage: SecureStorage,
    private credentialStore: ReturnType<typeof import("../state/index").createCredentialStore>,
  ) {}

  /** Parse an SD-JWT string into its components and reconstruct all claims. */
  parseSDJwt(sdJwtString: string): ParsedCredential {
    const parts = sdJwtString.split("~");
    const issuerJwt = parts[0];
    // Last element after final ~ is either KB-JWT or empty string
    const disclosureStrings = parts.slice(1, parts.length - 1).filter(Boolean);

    // Decode issuer JWT header and payload
    const [headerB64, payloadB64] = issuerJwt.split(".");
    const header = JSON.parse(
      new TextDecoder().decode(base64urlDecode(headerB64)),
    );
    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(payloadB64)),
    );

    // Decode each disclosure: base64url -> JSON array [salt, key, value]
    const disclosures = disclosureStrings.map((encoded) => {
      const decoded = JSON.parse(
        new TextDecoder().decode(base64urlDecode(encoded)),
      );
      return {
        encoded,
        salt: decoded[0] as string,
        key: decoded[1] as string,
        value: decoded[2] as unknown,
      };
    });

    // Reconstruct full claim set
    const claims: Record<string, unknown> = { ...payload };
    // Remove SD-JWT internal fields
    delete claims._sd;
    delete claims._sd_alg;
    // Add disclosed claims
    for (const d of disclosures) {
      claims[d.key] = d.value;
    }

    return { issuerJwt, disclosures, header, payload, claims };
  }

  /** Store a received SD-JWT credential. */
  async storeCredential(
    sdJwtString: string,
    issuerInfo: IssuerInfo,
  ): Promise<StoredCredential> {
    const parsed = this.parseSDJwt(sdJwtString);

    const id = crypto.randomUUID();
    const credentialType =
      (parsed.payload.vct as string) ??
      (parsed.payload.type as string) ??
      "UnknownCredential";

    const credential: StoredCredential = {
      id,
      sdJwt: sdJwtString,
      issuerDid: issuerInfo.issuerDid,
      credentialType,
      issuerName: issuerInfo.issuerName,
      issuedAt: (parsed.payload.iat as number) ?? Date.now() / 1000,
      expiresAt: (parsed.payload.exp as number) ?? 0,
      claims: parsed.claims,
    };

    // Store raw SD-JWT in secure storage
    await this.storage.set(`${CREDENTIAL_PREFIX}${id}`, sdJwtString);

    // Add to in-memory store and persist index
    const store = this.credentialStore.getState();
    store.addCredential(credential);
    await store.persistToStorage(this.storage);

    return credential;
  }

  /** Select disclosure strings for the requested claim names. */
  selectDisclosures(
    credential: StoredCredential,
    requestedClaims: string[],
  ): string[] {
    const parsed = this.parseSDJwt(credential.sdJwt);
    return parsed.disclosures
      .filter((d) => requestedClaims.includes(d.key))
      .map((d) => d.encoded);
  }

  /**
   * Build the final SD-JWT presentation string.
   * Format: issuerJwt~disclosure1~disclosure2~...~kbJwt
   */
  buildPresentationSDJwt(
    credential: StoredCredential,
    selectedDisclosures: string[],
    kbJwt: string,
  ): string {
    const issuerJwt = credential.sdJwt.split("~")[0];
    const disclosurePart = selectedDisclosures.join("~");
    return `${issuerJwt}~${disclosurePart}~${kbJwt}`;
  }

  /**
   * Compute sd_hash for KB-JWT: SHA-256 of the issuer JWT + selected disclosures
   * (everything before the KB-JWT in the presentation string).
   */
  computeSdHash(issuerJwt: string, selectedDisclosures: string[]): Uint8Array {
    const hashInput = `${issuerJwt}~${selectedDisclosures.join("~")}~`;
    return sha256(new TextEncoder().encode(hashInput));
  }

  /** Delete a credential from storage. */
  async deleteCredential(id: string): Promise<void> {
    await this.storage.delete(`${CREDENTIAL_PREFIX}${id}`);
    const store = this.credentialStore.getState();
    store.removeCredential(id);
    await store.persistToStorage(this.storage);
  }

  /** Load all credentials from storage into the store. */
  async loadAll(): Promise<void> {
    await this.credentialStore.getState().loadFromStorage(this.storage);
  }
}
