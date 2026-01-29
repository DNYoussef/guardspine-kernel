/**
 * Verification error codes for @guardspine/kernel.
 */

export enum ErrorCode {
  HASH_CHAIN_BROKEN = "HASH_CHAIN_BROKEN",
  ROOT_HASH_MISMATCH = "ROOT_HASH_MISMATCH",
  CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH",
  SIGNATURE_INVALID = "SIGNATURE_INVALID",
  SEQUENCE_GAP = "SEQUENCE_GAP",
  MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD",
}

export interface VerificationError {
  code: ErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

export interface VerificationResult {
  valid: boolean;
  errors: VerificationError[];
}
