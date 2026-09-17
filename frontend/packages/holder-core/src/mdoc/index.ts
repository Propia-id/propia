/**
 * ISO/IEC 18013-5 mdoc handling for the holder.
 *
 * Issuance-side parsing lives here; presentation (DeviceResponse, session
 * transcript, device auth) is built on top of the same primitives.
 */

export {
  claimKeyFor,
  displayValue,
  drivingPrivilegeCategories,
  flattenClaims,
  isBytesDescriptor,
  ISO_MDL_NAMESPACE,
  parseIssuerSigned,
  PORTRAIT_ELEMENT,
  portraitDataUri,
  readElementBytes,
  SOVRA_META_NAMESPACE,
  type BytesDescriptor,
  type ParsedMdoc,
  type ParsedMdocItem,
} from "./parse.js";

export {
  openId4VpHandoverInfo,
  sessionTranscript,
  SESSION_TRANSCRIPT_PROFILE,
  type HandoverInput,
} from "./session-transcript.js";

export {
  holderSignerToDeviceSigner,
  type DeviceSignature,
  type DeviceSigner,
} from "./device-signer.js";

export { buildDeviceResponse, type BuildDeviceResponseInput } from "./present.js";
