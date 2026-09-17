/**
 * Chain-only verification of an ISO 18013-5 mdoc presentation.
 *
 * The sibling of `verify.ts`, and the point of the whole exercise: a verifier
 * needs the presentation and read access to SovraChain, and nothing else. No
 * Sovra API, no database.
 *
 * That constraint shapes the design. A backend verifier can look a workspace up
 * by DID; this cannot, so everything it needs has to be either derivable from
 * the credential or readable from the chain. It is why the issued mdoc carries
 * a Sovra meta namespace at all.
 */

import {
  CborTagged,
  decode,
  encode,
  unwrapEmbedded,
  type CborMap,
  type CborValue,
} from "@sovrahq/holder-core/cbor";
import {
  COSE_ALG,
  coseKeyToXY,
  parseSign1,
  sig1ToBeSigned,
  sign1Alg,
  SOVRA_WEBAUTHN_LABEL,
  type CoseSign1,
} from "@sovrahq/holder-core/cose";
import { sessionTranscript } from "@sovrahq/holder-core/mdoc";
import { base64urlDecode, bytesToHex, keccak256, sha256 } from "@sovrahq/holder-core/utils";

import { VerificationCache } from "../cache.js";
import { VerificationError, validateEthAddress } from "../errors.js";
import { checkRevocation } from "../revocation.js";
import { extractHolderAddress, resolveHolderKeys } from "../resolve-holder.js";
import { checkIssuerTrust, resolveIssuerDID } from "../resolve-issuer.js";
import { verifyP256Raw, verifyWebAuthnAssertion } from "../signature.js";
import {
  ErrorCode,
  type HolderPasskey,
  type VerificationResult,
  type VerifyOptions,
} from "../types.js";
import { _defaultCache } from "../verify.js";
import { pemToDer, validateDocumentSignerChain, type DistinguishedName } from "../x509.js";
import {
  parseDeviceResponse,
  SOVRA_META_NAMESPACE,
  x5chainLeaf,
  type ParsedMdocPresentation,
} from "./parse-response.js";

/**
 * `expectedNonce` and `expectedAudience` are dropped rather than inherited.
 * They are how an SD-JWT presentation states its freshness and audience, in the
 * KB-JWT's own claims. An mdoc states both inside the session transcript, which
 * is what `clientId`, `nonce` and `responseUri` below reconstruct — so
 * inheriting them would make every mdoc verifier pass two values nothing reads.
 */
export interface VerifyMdocOptions extends Omit<VerifyOptions, "expectedNonce" | "expectedAudience"> {
  /** The `client_id` this verifier sent in its authorization request. */
  clientId: string;
  /** The one-time nonce from the same request. */
  nonce: string;
  /** The `response_uri` the presentation was posted to. */
  responseUri: string;
  /**
   * IACA root certificates this verifier accepts an mDL chain against — DER,
   * or a PEM bundle.
   *
   * Required to verify a credential under an ISO docType such as
   * `org.iso.18013.5.1.mDL`, which embeds no issuer address and is therefore
   * attributable only through its certificate. A generated Sovra docType
   * ignores this entirely.
   *
   * There is no default, and an empty list is not one: which authorities to
   * trust is the verifier's decision and cannot be inferred from the
   * credential, because the credential is what is being checked.
   */
  trustAnchors?: Uint8Array[] | string;
}

/**
 * What a validated chain establishes about the issuer, and all it establishes.
 *
 * Deliberately no address: an ISO Document Signer Certificate names a key and a
 * subject, and a Sovra workspace appears nowhere in either.
 */
interface CertificateAttestation {
  issuingAuthority?: string;
  documentSigner: DistinguishedName;
}

/**
 * Verify an mdoc `DeviceResponse`.
 *
 * Mirrors `verify/3`'s pipeline in intent: parse, resolve the issuer on-chain,
 * check the issuer signature and trust, re-hash the disclosed elements, check
 * validity and revocation, then verify the holder's device signature against
 * the keys their account currently authorizes.
 */
export async function verifyMdoc(
  deviceResponseB64u: string,
  options: VerifyMdocOptions,
  cache: VerificationCache = _defaultCache,
): Promise<VerificationResult> {
  const maxClockSkew = options.maxClockSkew ?? 60;

  try {
    const presentation = parseDeviceResponse(deviceResponseB64u);
    const { docType, mso, meta } = presentation;

    // Everything keyed by issuer — the revocation bitmaps, the trust registry —
    // uses the address the issuer signed into the meta namespace. A generated
    // docType carries the same address, and `checkAddressAgreement` requires
    // the two to match; an ISO docType carries none, which is what the
    // certificate route exists for.
    //
    // On that route the address is issuer-signed and nothing more: the chain
    // attests a key and a subject, never a workspace, so this value says who
    // the issuer claims to be. It is reported as `assertedIssuerAddress` rather
    // than as `issuer` for that reason.
    const issuerAddress = meta.issuerAddress;
    validateEthAddress(issuerAddress, "issuer");
    checkAddressAgreement(docType, issuerAddress);

    if (String(mso.get("docType")) !== docType) {
      throw new VerificationError(
        "MSO docType does not match the document",
        ErrorCode.DOCTYPE_MISMATCH,
      );
    }

    // Which route this credential is on, decided by the docType — the same
    // signal `Sovra.Mdoc.IssuerTrust` reads at issuance, so the two verifiers
    // and the issuer cannot disagree about how it is meant to be trusted.
    const certificateRoute = !isGeneratedDocType(docType);
    let attested: CertificateAttestation | undefined;

    if (certificateRoute) {
      // Offline mode skips *chain* reads, not this: a certificate chain needs
      // no network, so there is no reason to weaken the check. The signature is
      // verified either way.
      attested = verifyThroughCertificate(presentation, options);
    }

    if (!options.offlineMode && !certificateRoute) {
      let issuerKeys = cache.getIssuerKeys(issuerAddress);
      if (!issuerKeys) {
        issuerKeys = await resolveIssuerDID(
          options.l2RpcUrl,
          options.didRegistryAddress,
          issuerAddress,
        );
        cache.setIssuerKeys(issuerAddress, issuerKeys);
      }

      verifyIssuerAuth(presentation.issuerAuth, issuerKeys.pubKeyX, issuerKeys.pubKeyY);

      // Keyed by the registered credential type, not the docType — the docType
      // is derived from the schema and is not what the registry knows about.
      //
      // Skipped on the certificate route, where the chain *is* the authority
      // check: an IACA the verifier admitted has vouched for this signer, which
      // is a stronger statement than a registry entry and the one every reader
      // outside Sovra relies on.
      const typeId = bytesToHex(
        keccak256(new TextEncoder().encode(meta.credentialType)),
        false,
      );
      const cachedTrust = cache.getIssuerTrust(issuerAddress, typeId);
      if (cachedTrust === null) {
        await checkIssuerTrust(
          options.l2RpcUrl,
          options.issuerRegistryAddress,
          issuerAddress,
          meta.credentialType,
        );
        cache.setIssuerTrust(issuerAddress, typeId, true);
      } else if (!cachedTrust) {
        throw new VerificationError(
          `Issuer not trusted for credential type ${meta.credentialType}`,
          ErrorCode.ISSUER_NOT_TRUSTED,
        );
      }
    }

    verifyValueDigests(presentation);
    checkMandatoryElements(presentation);
    checkValidity(presentation, maxClockSkew);

    let revocationChecked = false;
    if (
      options.checkRevocation !== false &&
      !options.offlineMode &&
      options.revocationRegistryAddress
    ) {
      // An mdoc carries one index and both bitmaps apply to it, exactly as an
      // SD-JWT's two credentialStatus entries share theirs.
      for (const [label, purpose] of [["revoked", 0], ["suspended", 1]] as const) {
        let flagged = cache.getRevocationStatus(issuerAddress, meta.statusListIndex, purpose);

        if (flagged === null) {
          flagged = await checkRevocation(
            options.l2RpcUrl,
            options.revocationRegistryAddress,
            issuerAddress,
            meta.statusListIndex,
            purpose,
          );
          cache.setRevocationStatus(issuerAddress, meta.statusListIndex, purpose, flagged);
        }

        if (flagged) {
          throw new VerificationError(
            `Credential has been ${label}`,
            ErrorCode.CREDENTIAL_REVOKED,
          );
        }
      }
      revocationChecked = true;
    }

    await verifyDeviceAuth(presentation, options);

    return {
      valid: true,
      // A DID only where something attests one. On the generated route the
      // address selected the key this signature was verified against, so a
      // wrong address cannot reach here; on the certificate route nothing
      // attests it, and claiming otherwise would hand an integrator an
      // identity the chain never established.
      ...(attested
        ? {
            issuingAuthority: attested.issuingAuthority,
            documentSigner: attested.documentSigner,
            assertedIssuerAddress: issuerAddress,
          }
        : { issuer: `did:sovra:${issuerAddress}` }),
      holder: meta.holderDid,
      // The registered type, matching what the SD-JWT path returns here — not
      // the docType, which is derived from the schema and is not what the trust
      // registry is keyed by. The docType has its own field.
      credentialType: meta.credentialType,
      docType,
      offlineMode: options.offlineMode,
      claims: presentation.claims,
      issuedAt: presentation.validFrom,
      expiresAt: presentation.validUntil,
      revocationChecked,
    };
  } catch (error) {
    if (error instanceof VerificationError) {
      return { valid: false, error: error.message, errorCode: error.code };
    }
    throw error;
  }
}

// ── Steps ───────────────────────────────────────────────

/**
 * Establish the issuer's key from the `x5chain`, then verify `IssuerAuth`
 * against it.
 *
 * The order is the whole security argument. ISO puts `x5chain` in the
 * unprotected header, which the COSE signature does not cover — and that is
 * fine, because the chain only says which key to try. Substituting a different
 * chain substitutes a different key, and the signature then fails. Checking the
 * chain and concluding the credential is good, without verifying against the
 * key the chain named, accepts any forgery that ships a valid certificate.
 *
 * Returns what the chain actually establishes: the anchor that vouched, and the
 * signer it vouched for. That pair is the whole of the issuer's identity on
 * this route — there is no Sovra address anywhere in it, which is why
 * `verifyMdoc` reports the one in the meta namespace as asserted rather than as
 * `issuer`.
 */
function verifyThroughCertificate(
  presentation: ParsedMdocPresentation,
  options: VerifyMdocOptions,
): CertificateAttestation {
  const anchors = resolveTrustAnchors(options.trustAnchors);

  if (anchors.length === 0) {
    throw new VerificationError(
      `Verifying ${presentation.docType} needs trustAnchors: the docType carries no issuer ` +
        "address, so the certificate chain is the only way to attribute it",
      ErrorCode.ISSUER_NOT_TRUSTED,
    );
  }

  const leafDer = x5chainLeaf(presentation.issuerAuth);
  if (!leafDer) {
    throw new VerificationError(
      "Credential carries no x5chain, and its docType names no issuer",
      ErrorCode.ISSUER_NOT_TRUSTED,
    );
  }

  let leaf, anchor;
  try {
    ({ leaf, anchor } = validateDocumentSignerChain(leafDer, anchors));
  } catch (error) {
    throw new VerificationError(
      `Certificate chain rejected: ${error instanceof Error ? error.message : String(error)}`,
      ErrorCode.ISSUER_NOT_TRUSTED,
    );
  }

  verifyIssuerAuth(presentation.issuerAuth, leaf.publicKey.x, leaf.publicKey.y);

  return {
    ...(anchor.subject.commonName ? { issuingAuthority: anchor.subject.commonName } : {}),
    documentSigner: leaf.subject,
  };
}

function resolveTrustAnchors(anchors: Uint8Array[] | string | undefined): Uint8Array[] {
  if (!anchors) return [];
  return typeof anchors === "string" ? pemToDer(anchors) : anchors;
}

/**
 * Whether this docType is one Sovra generated, and so carries its own issuer
 * address: `io.sovra.<address>.<schema_id>.<version>`.
 *
 * Positional, not a scan for anything address-shaped — `schema_id` is
 * operator-chosen, and a schema called `0xdeadbeef` must not be mistaken for
 * the issuer. Lowercase only, because that is the single form the issuer emits
 * and the docType is a wire contract.
 *
 * `Sovra.Mdoc.DocType.issuer_address/1` is the same parse, and it is what
 * decides the route on the backend too. Keep them in step: the two verifiers
 * must accept the same set of credentials.
 */
function isGeneratedDocType(docType: string): boolean {
  const segments = docType.split(".");
  return (
    segments[0] === "io" &&
    segments[1] === "sovra" &&
    segments.length >= 4 &&
    /^0x[0-9a-f]{40}$/.test(segments[2] ?? "")
  );
}

/**
 * A generated docType embeds the issuer's address, and so does the meta
 * namespace. Both are issuer-signed, so they cannot disagree unless the
 * credential is malformed — and the docType is what a Sovra verifier resolves
 * the issuing workspace from, so a mismatch would mean one verifier attributes
 * the credential differently than another.
 */
function checkAddressAgreement(docType: string, issuerAddress: string): void {
  if (!isGeneratedDocType(docType)) return;

  if (docType.split(".")[2] !== issuerAddress) {
    throw new VerificationError(
      "docType and Sovra metadata name different issuers",
      ErrorCode.DOCTYPE_MISMATCH,
    );
  }
}

function verifyIssuerAuth(issuerAuth: CoseSign1, pubKeyX: Uint8Array, pubKeyY: Uint8Array): void {
  // The protected header only. An `alg` in the unprotected header carries no
  // authority, so honouring one would let a holder pick the weakest path.
  if (sign1Alg(issuerAuth) !== COSE_ALG.ES256) {
    throw new VerificationError(
      "issuerAuth is not an ES256 signature",
      ErrorCode.ISSUER_SIG_INVALID,
    );
  }

  const toBeSigned = sig1ToBeSigned(
    issuerAuth.protectedBytes,
    new Uint8Array(),
    issuerAuth.payload ?? new Uint8Array(),
  );

  if (!verifyP256Raw(issuerAuth.signature, sha256(toBeSigned), pubKeyX, pubKeyY, true)) {
    throw new VerificationError(
      "Issuer signature verification failed",
      ErrorCode.ISSUER_SIG_INVALID,
    );
  }
}

function verifyValueDigests(presentation: ParsedMdocPresentation): void {
  const { mso, items } = presentation;

  if (String(mso.get("digestAlgorithm")) !== "SHA-256") {
    throw new VerificationError(
      "Unsupported MSO digest algorithm",
      ErrorCode.MSO_DIGEST_MISMATCH,
    );
  }

  const valueDigests = mso.get("valueDigests");
  if (!(valueDigests instanceof Map)) {
    throw new VerificationError("MSO has no valueDigests", ErrorCode.MSO_DIGEST_MISMATCH);
  }

  for (const item of items) {
    const namespace = valueDigests.get(item.namespace);
    const expected = namespace instanceof Map ? namespace.get(item.digestId) : undefined;

    if (!(expected instanceof Uint8Array)) {
      throw new VerificationError(
        `No signed digest for ${item.namespace}/${item.elementIdentifier}`,
        ErrorCode.MSO_DIGEST_MISMATCH,
      );
    }

    // Over the wrapper rebuilt around the received payload — never re-encoded
    // from the decoded item, which would not reproduce it. The rebuild is
    // normalising, so it lands on the bytes the issuer signed.
    const actual = sha256(item.raw);
    if (actual.length !== expected.length || actual.some((b, i) => b !== expected[i])) {
      throw new VerificationError(
        `Element ${item.elementIdentifier} does not match its signed digest`,
        ErrorCode.MSO_DIGEST_MISMATCH,
      );
    }
  }
}

/**
 * Every element the issuer froze as non-withholdable must be present.
 *
 * Matched on `namespace + identifier`, not on the identifier alone: a document
 * carrying an ISO namespace and a domestic one can hold two `document_number`s,
 * and accepting whichever was disclosed would accept the wrong one.
 */
function checkMandatoryElements(presentation: ParsedMdocPresentation): void {
  const disclosed = new Set(
    presentation.items.map((i) => `${i.namespace}/${i.elementIdentifier}`),
  );

  for (const [namespace, elements] of Object.entries(presentation.meta.mandatoryElements)) {
    for (const required of elements) {
      if (!disclosed.has(`${namespace}/${required}`)) {
        throw new VerificationError(
          `Required element ${namespace}.${required} was not disclosed`,
          ErrorCode.DISCLOSURE_MISMATCH,
        );
      }
    }
  }
}

function checkValidity(presentation: ParsedMdocPresentation, maxClockSkew: number): void {
  const now = Math.floor(Date.now() / 1000);

  if (presentation.validUntil < now - maxClockSkew) {
    throw new VerificationError(
      `Credential expired at ${new Date(presentation.validUntil * 1000).toISOString()}`,
      ErrorCode.CREDENTIAL_EXPIRED,
    );
  }
  if (presentation.validFrom > now + maxClockSkew) {
    throw new VerificationError("Credential is not yet valid", ErrorCode.IAT_INVALID);
  }
}

async function verifyDeviceAuth(
  presentation: ParsedMdocPresentation,
  options: VerifyMdocOptions,
): Promise<void> {
  const { deviceAuth, docType, deviceNameSpacesBytes, meta } = presentation;

  // Rebuilt from what this verifier sent, never from anything the holder
  // supplied — which is what makes it a binding rather than a claim.
  const transcript = sessionTranscript({
    clientId: options.clientId,
    nonce: options.nonce,
    responseUri: options.responseUri,
  });

  const signedPayload = encode(
    new CborTagged(
      24,
      encode(["DeviceAuthentication", transcript, docType, deviceNameSpacesBytes]),
    ),
  );

  const toBeSigned = sig1ToBeSigned(
    deviceAuth.protectedBytes,
    new Uint8Array(),
    signedPayload,
  );

  const deviceKey = deviceKeyOf(presentation);

  // Issuance-time binding meets current on-chain authority. Trusting
  // MSO.deviceKey alone would let a passkey rotated away months ago keep
  // working — ISO-native, and a silent downgrade of our security model.
  // Offline mode has no chain to consult and so checks only the binding.
  if (!options.offlineMode) {
    const { passkeys } = await resolveHolderKeys(
      options.l2RpcUrl,
      extractHolderAddress(meta.holderDid),
    );

    if (!passkeys.some((k) => sameKey(k, deviceKey))) {
      throw new VerificationError(
        "The credential's device key is not currently authorized by the holder's account",
        ErrorCode.KB_PASSKEY_SIG_INVALID,
      );
    }
  }

  // Against the bound key alone: ISO §9.1.3 requires the signature to be by
  // that key, and the account's other keys are current but not bound.
  if (!verifyDeviceSignature(deviceAuth, toBeSigned, deviceKey)) {
    throw new VerificationError(
      "Device authentication failed — the presentation is not bound to this request",
      ErrorCode.DEVICE_AUTH_INVALID,
    );
  }
}

function verifyDeviceSignature(
  deviceAuth: CoseSign1,
  toBeSigned: Uint8Array,
  key: HolderPasskey,
): boolean {
  const alg = sign1Alg(deviceAuth);

  if (alg === COSE_ALG.ES256) {
    return verifyP256Raw(deviceAuth.signature, sha256(toBeSigned), key.x, key.y, false);
  }

  if (alg === COSE_ALG.SOVRA_WEBAUTHN_P256) {
    const assertion = webAuthnAssertionFrom(deviceAuth);
    return assertion ? verifyWebAuthnAssertion(assertion, toBeSigned, key.x, key.y) : false;
  }

  return false;
}

function webAuthnAssertionFrom(deviceAuth: CoseSign1) {
  const envelope = deviceAuth.unprotectedHeader.get(SOVRA_WEBAUTHN_LABEL);
  if (!(envelope instanceof Map)) return null;

  const authenticatorData = envelope.get("authenticator_data");
  const clientDataJson = envelope.get("client_data_json");
  const challengeIndex = envelope.get("challenge_index");
  const typeIndex = envelope.get("type_index");

  if (
    !(authenticatorData instanceof Uint8Array) ||
    !(clientDataJson instanceof Uint8Array) ||
    typeof challengeIndex !== "number" ||
    typeof typeIndex !== "number" ||
    deviceAuth.signature.length !== 64
  ) {
    return null;
  }

  return {
    r: deviceAuth.signature.subarray(0, 32),
    s: deviceAuth.signature.subarray(32),
    authenticatorData,
    client_data_json: new TextDecoder().decode(clientDataJson),
    challenge_index: challengeIndex,
    type_index: typeIndex,
  };
}

function deviceKeyOf(presentation: ParsedMdocPresentation): HolderPasskey {
  const info = presentation.mso.get("deviceKeyInfo");
  const key = info instanceof Map ? info.get("deviceKey") : undefined;

  if (key === undefined) {
    throw new VerificationError("MSO has no device key", ErrorCode.MDOC_PARSE_ERROR);
  }
  return coseKeyToXY(key as CborValue);
}

function sameKey(a: HolderPasskey, b: HolderPasskey): boolean {
  return (
    a.x.length === b.x.length &&
    a.y.length === b.y.length &&
    a.x.every((v, i) => v === b.x[i]) &&
    a.y.every((v, i) => v === b.y[i])
  );
}

export { SOVRA_META_NAMESPACE, decode, unwrapEmbedded, type CborMap };
