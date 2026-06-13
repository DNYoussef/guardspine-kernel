// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 GuardSpine, Inc.
// Licensed under the Business Source License 1.1. See LICENSE for terms.
// Change License: Apache-2.0. Change Date: see LICENSE.
/**
 * @guardspine/kernel -- offline evidence-bundle verification and sealing.
 * Zero runtime dependencies. Works in Node 18+ and modern browsers.
 */

// Canonical JSON (RFC 8785)
export { canonicalJson } from "./canonical.js";

// Sealing
export {
  GENESIS_HASH,
  computeContentHash,
  buildHashChain,
  computeRootHash,
  sealBundle,
} from "./seal.js";
export type { ChainInput, SealResult, ProofVersion, SealOptions } from "./seal.js";

// Verification
export {
  verifyHashChain,
  verifyRootHash,
  verifyContentHashes,
  verifySignatures,
  verifyBundle,
} from "./verify.js";
export type {
  SignatureVerificationOptions,
  ProofVerificationOptions,
  BundleVerificationOptions,
} from "./verify.js";

// Errors
export { ErrorCode } from "./errors.js";
export type { VerificationError, VerificationResult } from "./errors.js";

// Schema types
export type {
  EvidenceBundle,
  EvidenceItem,
  ImmutabilityProof,
  HashChainLink,
  HashChain,
} from "./schemas/evidence-bundle.js";

export type {
  PolicyPack,
  PolicyRule,
  PolicyCondition,
} from "./schemas/policy-pack.js";
