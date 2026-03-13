import type { ErrorCode } from "./types";

export class VerificationError extends Error {
  constructor(
    message: string,
    public code: ErrorCode,
  ) {
    super(message);
    this.name = "VerificationError";
  }
}

const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export function validateEthAddress(address: string, context: string): void {
  if (!ETH_ADDRESS_RE.test(address)) {
    throw new VerificationError(
      `Invalid Ethereum address in ${context}: ${address}`,
      "INVALID_ADDRESS" as ErrorCode,
    );
  }
}
