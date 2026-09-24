/**
 * The document an issuer attached to a credential — a PDF of the licence or
 * certificate the credential stands for.
 *
 * It arrives as an ordinary disclosable claim whose value is a `data:` URI, so
 * it is covered by the issuer's signature like every other claim. That is the
 * whole point of carrying it inside the credential: the holder can prove the
 * file is the one the issuer signed, offline, years later.
 *
 * It is also the largest thing the wallet ever receives, and `claims` is
 * persisted into the credential index — one secure-store value holding every
 * credential's metadata, on a store whose advisory limit is 2048 bytes. So the
 * URI never survives parsing: `parseSDJwt` swaps it for a descriptor, and the
 * disclosure is split out of the credential and moved to the asset store
 * before the credential is written. Same problem the mdoc portrait has, and the
 * same shape of answer — see `BytesDescriptor` in `../mdoc/parse.ts`.
 */

import { parseBase64DataUri } from "../utils/data-uri.js";

/** Media types the wallet will store, mapped to the extension its asset key carries. */
export const ATTACHMENT_MEDIA_TYPES: Record<string, string> = {
  "application/pdf": "pdf",
};

/**
 * Cap on the base64 payload accepted from an issuer.
 *
 * The backend refuses a `data:` URI over 560,000 bytes, so ~1.37x that clears
 * it with room for the server's own cap to move without needing a wallet
 * release — while still refusing to write an unbounded blob to disk. The role
 * `MAX_LOGO_BASE64_LENGTH` plays for artwork.
 */
export const MAX_ATTACHMENT_BASE64_LENGTH = 768 * 1024;

/**
 * What stands in for an attachment in `claims`.
 *
 * Deliberately not shaped like the mdoc `BytesDescriptor`: `isBytesDescriptor`
 * must stay false for one of these, or a renderer would fall through to the
 * "binary value" wording meant for a portrait and the row would say the wrong
 * thing.
 */
export interface AttachmentDescriptor {
  __attachment: true;
  mediaType: string;
  extension: string;
  /** Decoded size, for a size shown next to the document's name. */
  bytes: number;
}

/**
 * What opening an attached document came to.
 *
 * Two failures, because they are two different things to tell a holder: a
 * document that is no longer on the device, and one the wallet will not vouch
 * for because it is not what the issuer signed.
 */
export type AttachmentUri = { uri: string } | { error: "missing" | "tampered" };

export function isAttachmentDescriptor(value: unknown): value is AttachmentDescriptor {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as AttachmentDescriptor).__attachment === true
  );
}

/**
 * Read a claim value as an attachment, or null when it is not one.
 *
 * Null for an unsupported media type, for a payload past the cap and for one
 * no decoder accepts, so those values stay in `claims` as the strings they are
 * rather than being silently described as a document the wallet cannot
 * produce.
 */
export function parseAttachmentValue(
  value: unknown,
): { descriptor: AttachmentDescriptor; base64: string } | null {
  if (typeof value !== "string") return null;

  const dataUri = parseBase64DataUri(value, MAX_ATTACHMENT_BASE64_LENGTH);
  if (!dataUri) return null;

  // Matched exactly, not case-folded: the spec's value is
  // `data:application/pdf;…`, the backend admits no other spelling, and a
  // wallet that read two would be the one place they meet.
  const { mediaType, base64 } = dataUri;
  const extension = ATTACHMENT_MEDIA_TYPES[mediaType];
  if (!extension) return null;

  return {
    base64,
    descriptor: {
      __attachment: true,
      mediaType,
      extension,
      bytes: decodedLength(base64),
    },
  };
}

/** Decoded byte count, from the encoded length — no need to allocate the bytes. */
function decodedLength(base64: string): number {
  const padding = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  return (base64.length / 4) * 3 - padding;
}
