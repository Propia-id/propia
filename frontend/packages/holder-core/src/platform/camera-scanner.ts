/**
 * Platform-agnostic interface for QR code scanning.
 * Implementations: ExpoCameraScanner (mobile).
 */
export interface CameraScanner {
  /** Start scanning and return the decoded QR data. */
  scan(): Promise<string>;
}
