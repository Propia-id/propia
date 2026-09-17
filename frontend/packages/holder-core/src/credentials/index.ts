import type { AssetStorage, SecureStorage } from "../platform/index.js";
import type {
  StoredCredential,
  StoredMdocCredential,
  StoredSdJwtCredential,
  CredentialStore,
  CredentialDisplayMetadata,
  MdocElementMeta,
  StoredLogo,
  PendingLogo,
} from "../state/index.js";
import { credentialKey, logoAssetKey } from "../state/index.js";
import {
  claimKeyFor,
  flattenClaims,
  parseIssuerSigned,
  SOVRA_META_NAMESPACE,
} from "../mdoc/index.js";
import { sha256, base64urlDecode, base64urlEncode } from "../utils/index.js";

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
  display?: CredentialDisplayMetadata;
  claimLabels?: Record<string, string>;
  /**
   * The card logo off the issuer's OID4VCI `display`, still carrying its
   * bytes. Kept out of `display` because that shape is what gets persisted:
   * inline bytes are captured into the asset store first and only the
   * resulting reference is written.
   */
  logo?: PendingLogo;
}

/** A random UUIDv4-shaped identifier. `crypto.randomUUID` is absent under Hermes. */
function newCredentialId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const h = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ─── Credential Manager ──────────────────────────────

export class CredentialManager {
  /**
   * Active wallet namespace — the lowercased wallet address. Credentials are
   * scoped to it so one holder never sees another's. Set on sign-in (and
   * cleared to null on sign-out) via the app's session wiring.
   */
  private namespace: string | null = null;

  constructor(
    private storage: SecureStorage,
    private credentialStore: ReturnType<typeof import("../state/index.js").createCredentialStore>,
    /**
     * Where inline card art is captured. Optional: without it a credential is
     * stored exactly as before and its card falls back to the app's brand
     * mark, which is what a host with no filesystem (tests, web) should do.
     */
    private assets?: AssetStorage,
  ) {}

  /** Scope all subsequent credential operations to `address` (null = none). */
  setActiveWallet(address: string | null): void {
    this.namespace = address ? address.toLowerCase() : null;
  }

  private requireNamespace(): string {
    if (!this.namespace) {
      throw new Error(
        "CredentialManager: no active wallet — call setActiveWallet() after sign-in",
      );
    }
    return this.namespace;
  }

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
  ): Promise<StoredSdJwtCredential> {
    const ns = this.requireNamespace();
    const parsed = this.parseSDJwt(sdJwtString);

    const id = newCredentialId();
    const credentialType =
      (parsed.payload.vct as string) ??
      (parsed.payload.type as string) ??
      "UnknownCredential";

    const logo = await this.captureLogo(id, issuerInfo.logo);
    const display = logo
      ? { ...(issuerInfo.display ?? {}), logo }
      : issuerInfo.display;

    const credential: StoredSdJwtCredential = {
      id,
      format: "vc+sd-jwt",
      sdJwt: sdJwtString,
      issuerDid: issuerInfo.issuerDid,
      credentialType,
      issuerName: issuerInfo.issuerName,
      issuedAt: (parsed.payload.iat as number) ?? Date.now() / 1000,
      expiresAt: (parsed.payload.exp as number) ?? 0,
      claims: parsed.claims,
      ...(display ? { display } : {}),
      ...(issuerInfo.claimLabels ? { claimLabels: issuerInfo.claimLabels } : {}),
    };

    // Add to in-memory store and persist under the active wallet's namespace.
    // persistToStorage writes the index + each raw SD-JWT (including this one).
    const store = this.credentialStore.getState();
    store.addCredential(credential);
    await store.persistToStorage(this.storage, ns);

    return credential;
  }

  /**
   * Store a received mdoc credential.
   *
   * `parseIssuerSigned` reads the docType out of the signed MSO rather than
   * from any wrapper, so a credential cannot claim to be one type while being
   * signed as another.
   */
  async storeMdocCredential(
    issuerSignedB64u: string,
    issuerInfo: IssuerInfo,
  ): Promise<StoredMdocCredential> {
    const ns = this.requireNamespace();
    const parsed = parseIssuerSigned(issuerSignedB64u);

    const elements: MdocElementMeta[] = parsed.items
      .filter((item) => item.namespace !== SOVRA_META_NAMESPACE)
      .map((item) => ({
        namespace: item.namespace,
        elementIdentifier: item.elementIdentifier,
        claimKey: claimKeyFor(item, parsed.namespace),
        // Frozen by the issuer at issuance, so a later schema revision cannot
        // change what this credential is required to disclose. Looked up under
        // the item's own namespace: an element identifier is only unique
        // within one.
        mandatory: (parsed.mandatoryElements[item.namespace] ?? []).includes(
          item.elementIdentifier,
        ),
      }));

    const id = newCredentialId();
    const logo = await this.captureLogo(id, issuerInfo.logo);
    const display = logo
      ? { ...(issuerInfo.display ?? {}), logo }
      : issuerInfo.display;

    const credential: StoredMdocCredential = {
      id,
      format: "mso_mdoc",
      issuerSigned: issuerSignedB64u,
      docType: parsed.docType,
      // credentialType carries the docType so type-based lookups, colours and
      // categories work across both formats off one field.
      credentialType: parsed.docType,
      issuerDid: issuerInfo.issuerDid,
      issuerName: issuerInfo.issuerName,
      issuedAt: parsed.validFrom,
      expiresAt: parsed.validUntil,
      claims: flattenClaims(parsed.items, parsed.namespace),
      elements,
      ...(display ? { display } : {}),
      ...(issuerInfo.claimLabels ? { claimLabels: issuerInfo.claimLabels } : {}),
    };

    const store = this.credentialStore.getState();
    store.addCredential(credential);
    await store.persistToStorage(this.storage, ns);

    return credential;
  }

  /**
   * The mdoc elements to disclose for a set of requested claim keys.
   *
   * Every mandatory element is unioned in regardless of what was requested or
   * deselected. This is the enforcement point for the schema's
   * `disclosable: false`; the disabled toggle in the approval screen is a
   * courtesy on top of it.
   */
  selectMdocElements(
    credential: StoredMdocCredential,
    requestedClaimKeys: string[],
  ): MdocElementMeta[] {
    return credential.elements.filter(
      (element) => element.mandatory || requestedClaimKeys.includes(element.claimKey),
    );
  }

  /**
   * Persist the issuer's card logo and return the reference to store.
   *
   * A remote URL is kept as it stands. Inline bytes are written to the asset
   * store, which is where the size lives — never the credential index. A
   * failed write is swallowed: a credential the holder just accepted must not
   * be lost over its artwork, and a card with no logo still renders on the
   * app's brand mark.
   */
  private async captureLogo(
    credentialId: string,
    logo: PendingLogo | undefined,
  ): Promise<StoredLogo | undefined> {
    if (!logo) return undefined;
    if (logo.kind === "url") {
      return { source: "url", url: logo.url, ...(logo.alt ? { alt: logo.alt } : {}) };
    }
    if (!this.assets) return undefined;

    const key = logoAssetKey(credentialId, logo.extension);
    try {
      await this.assets.put(key, logo.base64);
    } catch (err) {
      console.warn("Could not store the issuer's card logo:", err);
      return undefined;
    }
    return { source: "asset", key, ...(logo.alt ? { alt: logo.alt } : {}) };
  }

  /** Select disclosure strings for the requested claim names. */
  selectDisclosures(
    credential: StoredSdJwtCredential,
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
    credential: StoredSdJwtCredential,
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

  /** Delete a credential from the active wallet's storage. */
  async deleteCredential(id: string): Promise<void> {
    const ns = this.requireNamespace();
    const captured = this.credentialStore.getState().getCredential(id)?.display?.logo;
    await this.storage.delete(credentialKey(ns, id));
    const store = this.credentialStore.getState();
    store.removeCredential(id);
    await store.persistToStorage(this.storage, ns);

    // Last: the credential is already gone, so a failure here leaks a file
    // rather than leaving a card pointing at art that was deleted under it.
    if (captured?.source === "asset" && this.assets) {
      await this.assets.delete(captured.key).catch(() => {});
    }
  }

  /**
   * Load the active wallet's credentials into the store. With no active
   * wallet set (signed out / session restoring), clears the in-memory list.
   */
  async loadAll(): Promise<void> {
    const store = this.credentialStore.getState();
    if (!this.namespace) {
      store.reset();
      return;
    }
    await store.loadFromStorage(this.storage, this.namespace);
  }
}
