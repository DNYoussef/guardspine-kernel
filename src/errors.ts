// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 GuardSpine, Inc.
// Licensed under the Business Source License 1.1. See LICENSE for terms.
// Change License: Apache-2.0. Change Date: see LICENSE.
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
  INPUT_VALIDATION_FAILED = "INPUT_VALIDATION_FAILED",
  LENGTH_MISMATCH = "LENGTH_MISMATCH",
  UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION",
  SIGNATURE_REQUIRED = "SIGNATURE_REQUIRED",
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
