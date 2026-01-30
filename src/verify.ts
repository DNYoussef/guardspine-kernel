/**
 * Offline bundle verification for @guardspine/kernel.
 * Verifies hash chains, root hashes, and content integrity.
 *
 * Trace: Each verification function returns a VerificationResult
 * with explicit error codes, enabling callers to determine exactly
 * which step failed and why. Decisions are logged via error detail objects.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { canonicalJson } from "./canonical.js";
import { ErrorCode } from "./errors.js";
import type { VerificationError, VerificationResult } from "./errors.js";
import type {
  EvidenceBundle,
  EvidenceItem,
  HashChain,
  ImmutabilityProof,
} from "./schemas/evidence-bundle.js";

/**
 * Constant-time string comparison to prevent timing side-channel attacks.
 * Both strings are converted to Buffers of equal length before comparison.
 */
function safeEqual(left: string, right: string): boolean {
  const bufLeft = Buffer.from(left, "utf-8");
  const bufRight = Buffer.from(right, "utf-8");
  if (bufLeft.length !== bufRight.length) {
    return false;
  }
  return timingSafeEqual(bufLeft, bufRight);
}

function sha256(data: string): string {
  return `sha256:${createHash("sha256").update(data, "utf-8").digest("hex")}`;
}

function contentHash(content: object): string {
  return sha256(canonicalJson(content));
}

/**
 * Verify that each link in the chain correctly references the previous link
 * and that the chain_hash is computed correctly.
 *
 * Trace rationale: walks the chain sequentially, checking sequence numbers,
 * previous_hash linkage, and recomputed chain_hash. Any mismatch produces
 * a typed error with the expected vs actual values for audit traceability.
 */
export function verifyHashChain(chain: HashChain): VerificationResult {
  const errors: VerificationError[] = [];

  for (let i = 0; i < chain.length; i++) {
    const link = chain[i];

    // Check sequence
    if (link.sequence !== i) {
      errors.push({
        code: ErrorCode.SEQUENCE_GAP,
        message: `Expected sequence ${i}, got ${link.sequence}`,
        details: { expected: i, actual: link.sequence },
      });
    }

    // Check previous_hash
    const expectedPrev = i === 0 ? "genesis" : chain[i - 1].chain_hash;
    if (!safeEqual(link.previous_hash, expectedPrev)) {
      errors.push({
        code: ErrorCode.HASH_CHAIN_BROKEN,
        message: `Chain broken at sequence ${i}: previous_hash mismatch`,
        details: {
          sequence: i,
          expected: expectedPrev,
          actual: link.previous_hash,
        },
      });
    }

    // Recompute chain_hash
    const chainInput = `${link.sequence}|${link.content_hash}|${link.previous_hash}`;
    const expected = sha256(chainInput);
    if (!safeEqual(link.chain_hash, expected)) {
      errors.push({
        code: ErrorCode.HASH_CHAIN_BROKEN,
        message: `Chain hash mismatch at sequence ${i}`,
        details: {
          sequence: i,
          expected,
          actual: link.chain_hash,
        },
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Verify the root hash matches the concatenation of all chain hashes.
 *
 * Trace rationale: the root hash is a single SHA-256 over all concatenated
 * chain hashes. A mismatch indicates the chain was modified after sealing.
 */
export function verifyRootHash(proof: ImmutabilityProof): VerificationResult {
  const errors: VerificationError[] = [];

  const concat = proof.hash_chain.map((link) => link.chain_hash).join("");
  const expected = sha256(concat);

  if (!safeEqual(proof.root_hash, expected)) {
    errors.push({
      code: ErrorCode.ROOT_HASH_MISMATCH,
      message: "Root hash does not match computed value",
      details: { expected, actual: proof.root_hash },
    });
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Verify that each item's content_hash matches SHA-256 of its canonical content.
 *
 * Trace rationale: recomputes SHA-256 of each item's canonical JSON and
 * compares against the stored content_hash. Detects content tampering.
 */
export function verifyContentHashes(items: EvidenceItem[]): VerificationResult {
  const errors: VerificationError[] = [];

  for (const item of items) {
    const expected = contentHash(item.content);
    if (!safeEqual(item.content_hash, expected)) {
      errors.push({
        code: ErrorCode.CONTENT_HASH_MISMATCH,
        message: `Content hash mismatch for item ${item.item_id}`,
        details: {
          item_id: item.item_id,
          expected,
          actual: item.content_hash,
        },
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Full bundle verification: required fields, content hashes, chain, root.
 *
 * Trace rationale: orchestrates all sub-verifications (content hashes, hash
 * chain, root hash, cross-check) and aggregates errors. Returns early if
 * critical fields are missing. Each error carries typed code and details
 * for deterministic audit trail reconstruction.
 */
export function verifyBundle(bundle: EvidenceBundle): VerificationResult {
  const errors: VerificationError[] = [];

  // Check required fields
  const requiredFields: (keyof EvidenceBundle)[] = [
    "bundle_id",
    "version",
    "created_at",
    "items",
    "immutability_proof",
  ];

  for (const field of requiredFields) {
    if (bundle[field] === undefined || bundle[field] === null) {
      errors.push({
        code: ErrorCode.MISSING_REQUIRED_FIELD,
        message: `Missing required field: ${field}`,
        details: { field },
      });
    }
  }

  // If critical fields missing, return early
  if (!bundle.items || !bundle.immutability_proof) {
    return { valid: false, errors };
  }

  // Verify content hashes
  const contentResult = verifyContentHashes(bundle.items);
  errors.push(...contentResult.errors);

  // Verify hash chain
  const chainResult = verifyHashChain(bundle.immutability_proof.hash_chain);
  errors.push(...chainResult.errors);

  // Verify root hash
  const rootResult = verifyRootHash(bundle.immutability_proof);
  errors.push(...rootResult.errors);

  // Cross-check: chain content_hash should match item content_hash
  const chain = bundle.immutability_proof.hash_chain;
  for (let i = 0; i < bundle.items.length && i < chain.length; i++) {
    if (!safeEqual(bundle.items[i].content_hash, chain[i].content_hash)) {
      errors.push({
        code: ErrorCode.CONTENT_HASH_MISMATCH,
        message: `Item ${i} content_hash does not match chain link`,
        details: {
          sequence: i,
          item_hash: bundle.items[i].content_hash,
          chain_hash: chain[i].content_hash,
        },
      });
    }
  }

  return { valid: errors.length === 0, errors };
}
