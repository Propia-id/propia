/**
 * Builds the `DeviceResponse` an mdoc presentation posts back to a verifier.
 *
 * Selective disclosure is subtractive: the issuer signed digests over every
 * element, and withholding one simply omits its `IssuerSignedItemBytes` from
 * the response. The `issuerAuth` signature is untouched and still verifies —
 * which is why the disclosed items must carry their **original** bytes rather
 * than anything re-encoded from a decoded value.
 */

import {
  CborTagged,
  decode,
  embed,
  encode,
  type CborMap,
  type CborValue,
} from "../cbor/index.js";
import { COSE_HEADER, encodeSign1, sig1ToBeSigned } from "../cose/index.js";
import { base64urlEncode, sha256 } from "../utils/index.js";
import type { DeviceSigner } from "./device-signer.js";
import { sessionTranscript, type HandoverInput } from "./session-transcript.js";
import type { ParsedMdoc, ParsedMdocItem } from "./parse.js";

/** ISO 18013-5 `DeviceResponse.status`: 0 is OK. */
const STATUS_OK = 0;
const VERSION = "1.0";

export interface BuildDeviceResponseInput {
  parsed: ParsedMdoc;
  /** The items to disclose. Everything else is omitted. */
  disclosed: ParsedMdocItem[];
  handover: HandoverInput;
  signer: DeviceSigner;
}

export async function buildDeviceResponse({
  parsed,
  disclosed,
  handover,
  signer,
}: BuildDeviceResponseInput): Promise<string> {
  // We sign no device-supplied elements, so DeviceNameSpaces is empty. That is
  // deliberate: anything here would be holder-asserted data with no issuer
  // signature behind it, and a verifier has no basis to trust it.
  const deviceNameSpacesBytes = embed(new Map());

  const deviceAuthentication: CborValue = [
    "DeviceAuthentication",
    sessionTranscript(handover),
    parsed.docType,
    deviceNameSpacesBytes,
  ];

  const protectedHeader: CborMap = new Map<number, CborValue>([
    [COSE_HEADER.ALG, signer.coseAlg],
  ]);
  const protectedBytes = encode(protectedHeader);

  // Detached payload: DeviceAuthenticationBytes is what the signature covers,
  // but it is not transmitted — the verifier rebuilds it from its own session.
  const signedPayload = encode(embed(deviceAuthentication));
  const toBeSigned = sig1ToBeSigned(protectedBytes, new Uint8Array(), signedPayload);

  const { signature, unprotected } = await signer.signCose(toBeSigned);

  const deviceSignature = encodeSign1({
    protectedBytes,
    protectedHeader,
    unprotectedHeader: unprotected,
    payload: null,
    signature,
  });

  const document = new Map<string, CborValue>([
    ["docType", parsed.docType],
    [
      "issuerSigned",
      new Map<string, CborValue>([
        ["nameSpaces", disclosedNameSpaces(disclosed)],
        // Re-encoding the parsed COSE_Sign1 reproduces the issuer's original
        // bytes, because every field it holds is kept verbatim.
        ["issuerAuth", decode(encodeSign1(parsed.issuerAuth))],
      ]),
    ],
    [
      "deviceSigned",
      new Map<string, CborValue>([
        ["nameSpaces", deviceNameSpacesBytes],
        [
          "deviceAuth",
          new Map<string, CborValue>([["deviceSignature", decode(deviceSignature)]]),
        ],
      ]),
    ],
  ]);

  const response = new Map<string, CborValue>([
    ["version", VERSION],
    ["documents", [document]],
    ["status", STATUS_OK],
  ]);

  return base64urlEncode(encode(response));
}

/** Group the disclosed items by namespace, keeping their bytes exactly as issued. */
function disclosedNameSpaces(disclosed: ParsedMdocItem[]): CborMap {
  const out = new Map<string, CborValue>();

  for (const item of disclosed) {
    const existing = out.get(item.namespace);
    const list = Array.isArray(existing) ? existing : [];
    // `decode` of the stored wrapper yields the tagged value; encoding it again
    // reproduces the issuer's bytes byte for byte.
    list.push(decode(item.raw) as CborTagged);
    out.set(item.namespace, list);
  }
  return out;
}

export { sha256 };
