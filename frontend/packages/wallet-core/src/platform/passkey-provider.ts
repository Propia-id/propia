/**
 * Platform-agnostic interface for P256 passkey operations.
 * Implementations: NativePasskeyProvider (mobile), WebAuthnPasskeyProvider (web).
 */
export interface PasskeyProvider {
  /** Create a new P256 passkey and return the public key. */
  create(userId: string, displayName: string): Promise<PasskeyResult>;

  /** Sign data with an existing passkey. */
  sign(credentialId: string, challenge: Uint8Array): Promise<PasskeySignature>;
}

export interface PasskeyResult {
  credentialId: string;
  publicKey: Uint8Array;
}

export interface PasskeySignature {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
}
