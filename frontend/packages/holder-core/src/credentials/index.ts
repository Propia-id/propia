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
  StoredAttachment,
} from "../state/index.js";
import {
  attachmentAssetKey,
  attachmentDisclosureAssetKey,
  credentialKey,
  isSdJwt,
  logoAssetKey,
} from "../state/index.js";
import {
  parseAttachmentValue,
  type AttachmentDescriptor,
  type AttachmentUri,
} from "./attachment.js";
import {
  claimKeyFor,
  flattenClaims,
  parseIssuerSigned,
  SOVRA_META_NAMESPACE,
} from "../mdoc/index.js";
import type { EthCall } from "../did/index.js";
import { readRegistryStatuses } from "../status/index.js";
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
  /**
   * The attached document, if the credential carries one. Reported here rather
   * than left in `claims`, which is persisted into the credential index.
   */
  attachment?: {
    key: string;
    disclosure: string;
    descriptor: AttachmentDescriptor;
  };
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

    // An attachment is recognised by looking at the value, never by trusting
    // the issuer's metadata to say which claim it is. Metadata is fetched once,
    // during issuance — but a credential also arrives through a backup restore,
    // which calls `storeCredential` with none at all. A metadata-driven flag
    // would leave that path writing a half-megabyte data URI into the
    // credential index, which is a single secure-store value holding every
    // credential's metadata. The parser sees every path into storage.
    let attachment: ParsedCredential["attachment"];
    for (const d of disclosures) {
      const parsed = parseAttachmentValue(d.value);
      if (!parsed) continue;
      claims[d.key] = parsed.descriptor;
      // First one wins: the backend admits one per schema, and a second would
      // have nowhere of its own to go.
      attachment ??= {
        key: d.key,
        disclosure: d.encoded,
        descriptor: parsed.descriptor,
      };
    }

    return {
      issuerJwt,
      disclosures,
      header,
      payload,
      claims,
      ...(attachment ? { attachment } : {}),
    };
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

    // Split out whenever there is an asset store, even if the capture failed.
    // The blob goes into the platform secure store, which cannot hold a
    // document: kept whole, the write fails and the holder loses the credential
    // over what came attached to it. Losing only the document is the lesser
    // failure, and it is not a silent one — the reference stays, so opening it
    // reports the document missing.
    //
    // With no asset store at all — the Node and e2e assemblies, whose storage
    // has no such limit — the credential is stored whole, because there the
    // SD-JWT is the only place the document can live.
    const attachment = await this.captureAttachment(id, parsed.attachment);
    const sdJwt =
      attachment && parsed.attachment
        ? stripDisclosure(sdJwtString, parsed.attachment.disclosure)
        : sdJwtString;

    const credential: StoredSdJwtCredential = {
      id,
      format: "vc+sd-jwt",
      sdJwt,
      issuerDid: issuerInfo.issuerDid,
      credentialType,
      issuerName: issuerInfo.issuerName,
      issuedAt: (parsed.payload.iat as number) ?? Date.now() / 1000,
      expiresAt: (parsed.payload.exp as number) ?? 0,
      claims: parsed.claims,
      ...(display ? { display } : {}),
      ...(issuerInfo.claimLabels ? { claimLabels: issuerInfo.claimLabels } : {}),
      ...(attachment ? { attachment } : {}),
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

  /**
   * Persist an attached document and return the reference to store.
   *
   * One write: the disclosure the document arrived in, verbatim. It is the only
   * copy the wallet keeps — `attachmentUri` writes the file the holder opens
   * out of it, after checking it against the issuer's signature. Stored rather
   * than re-derived from the salt and the value: the digest has to match
   * SHA-256 over the exact string the issuer hashed, and re-deriving it would
   * make the wallet depend on `JSON.stringify` matching Elixir's encoder byte
   * for byte, forever, with a divergence failing silently at a verifier.
   *
   * `undefined` only when there is no asset store. A failed write still
   * returns the reference, with nothing behind it: `storeCredential` strips the
   * disclosure either way, and `attachmentUri` then reports the document
   * missing — which, for the holder, is exactly what it is.
   */
  private async captureAttachment(
    credentialId: string,
    attachment: ParsedCredential["attachment"],
  ): Promise<StoredAttachment | undefined> {
    if (!attachment || !this.assets) return undefined;

    const key = attachmentAssetKey(credentialId, attachment.descriptor.extension);
    const disclosureKey = attachmentDisclosureAssetKey(credentialId);

    try {
      // `put` takes standard base64 and writes the bytes it decodes, and `text`
      // reads bytes back as UTF-8. A disclosure is ASCII — the base64url
      // alphabet — so `btoa` round-trips it exactly. base64url would not: the
      // platform decoders refuse `-`, `_` and missing padding.
      await this.assets.put(disclosureKey, btoa(attachment.disclosure));
    } catch (err) {
      console.warn("Could not store the credential's attached document:", err);
      // A half-written file would read back as a disclosure the issuer never
      // signed, and the holder would be told the document was tampered with.
      await this.assets.delete(disclosureKey).catch(() => {});
    }

    return {
      claim: attachment.key,
      key,
      disclosureKey,
      mediaType: attachment.descriptor.mediaType,
      bytes: attachment.descriptor.bytes,
    };
  }

  /**
   * The disclosure a credential's attached document arrived in, as stored.
   *
   * Unverified: `attachmentUri` checks it against the issuer's signature before
   * using it. Outside that, nothing calls this today — the attachment is
   * withheld from every presentation. It exists so that a flow which genuinely
   * needs to present one can concatenate the result into the disclosures it
   * passes to `buildPresentationSDJwt` and `computeSdHash`, both of which take
   * disclosure strings rather than the credential, so neither needs changing
   * for that to work.
   */
  async loadAttachmentDisclosure(
    credential: StoredCredential,
  ): Promise<string | null> {
    if (!isSdJwt(credential) || !credential.attachment || !this.assets) return null;
    return this.assets.text(credential.attachment.disclosureKey);
  }

  /**
   * Write a credential's attached document to a file, from a disclosure
   * verified against the issuer's signature, and return a URI for it.
   *
   * The file is written from the disclosure every time rather than kept beside
   * it. The disclosure lives in ordinary app storage, not the secure store, so
   * its digest is checked against the `_sd` array the issuer signed; a file
   * derived from a checked disclosure is then the signed document by
   * construction, and there is no second copy on disk that could drift from
   * it unnoticed.
   *
   * `null` when the credential carries no document; `missing` when its
   * disclosure is gone; `tampered` when the disclosure is not one the issuer
   * signed. Throws when the file cannot be written.
   */
  async attachmentUri(credential: StoredCredential): Promise<AttachmentUri | null> {
    if (!isSdJwt(credential) || !credential.attachment || !this.assets) return null;

    const disclosure = await this.loadAttachmentDisclosure(credential);
    if (!disclosure) return { error: "missing" };

    const digest = base64urlEncode(sha256(utf8(disclosure)));
    const signed = this.parseSDJwt(credential.sdJwt).payload._sd;
    if (!Array.isArray(signed) || !signed.includes(digest)) return { error: "tampered" };

    // Signed, and read as a document when it arrived, so a null here is a
    // wallet whose own rules moved — not a file anyone altered.
    const document = parseAttachmentValue(disclosureValue(disclosure));
    if (!document) throw new Error("The signed attachment no longer reads as a document");

    const { key } = credential.attachment;
    await this.assets.put(key, document.base64);
    const uri = this.assets.uriFor(key);
    if (!uri) throw new Error(`No file URI for ${key}`);
    return { uri };
  }

  /**
   * Select disclosure strings for the requested claim names.
   *
   * An attached document is never among them. Its disclosure was split out of
   * `sdJwt` at issuance, so this cannot reach it even if a verifier asks — and
   * that is the intended default: a verifier asking for a driving licence gets
   * the claims, not the scan. `loadAttachmentDisclosure` is the deliberate way
   * back, for a flow that has a reason.
   */
  selectDisclosures(
    credential: StoredSdJwtCredential,
    requestedClaims: string[],
  ): string[] {
    if (credential.attachment && requestedClaims.includes(credential.attachment.claim)) {
      // Silently returning one fewer disclosure than was asked for is the kind
      // of gap that is impossible to diagnose from a verifier's side.
      console.warn(
        `[credentials] ${credential.attachment.claim} is an attached document and is ` +
          `withheld from presentations`,
      );
    }

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
    const existing = this.credentialStore.getState().getCredential(id);
    const captured = existing?.display?.logo;
    const attachment = existing && isSdJwt(existing) ? existing.attachment : undefined;
    await this.storage.delete(credentialKey(ns, id));
    const store = this.credentialStore.getState();
    store.removeCredential(id);
    await store.persistToStorage(this.storage, ns);

    // Last: the credential is already gone, so a failure here leaks a file
    // rather than leaving a card pointing at art that was deleted under it.
    if (captured?.source === "asset" && this.assets) {
      await this.assets.delete(captured.key).catch(() => {});
    }
    if (attachment && this.assets) {
      await this.assets.delete(attachment.key).catch(() => {});
      await this.assets.delete(attachment.disclosureKey).catch(() => {});
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

  /**
   * Re-read the active wallet's credentials against the revocation registry
   * and persist whatever changed.
   *
   * A credential whose issuer's lists cannot be read keeps its last known
   * status. The wallet may switch while the reads are in flight; their answers
   * then belong to a holder who is no longer loaded, and are dropped.
   */
  async refreshRegistryStatuses(ethCall: EthCall, registryAddress: string): Promise<void> {
    const ns = this.namespace;
    if (!ns) return;

    const statuses = await readRegistryStatuses(
      ethCall,
      registryAddress,
      this.credentialStore.getState().credentials,
    );
    if (this.namespace !== ns) return;

    const store = this.credentialStore.getState();
    if (store.setRegistryStatuses(statuses)) {
      await store.persistToStorage(this.storage, ns);
    }
  }
}

/** UTF-8 bytes. Named because the alternative reads as noise at every call site. */
function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** The value a disclosure carries, or undefined when it is not a `[salt, key, value]`. */
function disclosureValue(disclosure: string): unknown {
  try {
    const decoded = JSON.parse(new TextDecoder().decode(base64urlDecode(disclosure)));
    return Array.isArray(decoded) && decoded.length === 3 ? decoded[2] : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Remove one disclosure from a compact SD-JWT.
 *
 * Lossless: the disclosure's digest stays in the signed `_sd` array, so what
 * comes back is an ordinary credential with one claim withheld — the state a
 * holder creates every time they decline to disclose something. The issuer JWT
 * is untouched, so the signature still verifies, and re-appending the segment
 * reconstructs the original byte for byte.
 */
function stripDisclosure(sdJwt: string, disclosure: string): string {
  const parts = sdJwt.split("~");
  const [jwt, ...rest] = parts;
  return [jwt, ...rest.filter((segment) => segment !== disclosure)].join("~");
}
