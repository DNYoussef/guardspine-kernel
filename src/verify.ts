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
import { GENESIS_HASH } from "./seal.js";
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

  if (!Array.isArray(chain) || chain.length === 0) {
    errors.push({
      code: ErrorCode.INPUT_VALIDATION_FAILED,
      message: "Hash chain must be a non-empty array",
      details: { received: Array.isArray(chain) ? "empty array" : typeof chain },
    });
    return { valid: false, errors };
  }

  for (let seq = 0; seq < chain.length; seq++) {
    const link = chain[seq];

    // Check sequence
    if (link.sequence !== seq) {
      errors.push({
        code: ErrorCode.SEQUENCE_GAP,
        message: `Expected sequence ${seq}, got ${link.sequence}`,
        details: { expected: seq, actual: link.sequence },
      });
    }

    // Check previous_hash
    const expectedPrev = seq === 0 ? GENESIS_HASH : chain[seq - 1].chain_hash;
    if (!safeEqual(link.previous_hash, expectedPrev)) {
      errors.push({
        code: ErrorCode.HASH_CHAIN_BROKEN,
        message: `Chain broken at sequence ${seq}: previous_hash mismatch`,
        details: {
          sequence: seq,
          expected: expectedPrev,
          actual: link.previous_hash,
        },
      });
    }

    // Recompute chain_hash (v0.2.0: includes item_id and content_type)
    const chainInput = `${link.sequence}|${link.item_id ?? ""}|${link.content_type ?? ""}|${link.content_hash}|${link.previous_hash}`;
    const expected = sha256(chainInput);
    if (!safeEqual(link.chain_hash, expected)) {
      errors.push({
        code: ErrorCode.HASH_CHAIN_BROKEN,
        message: `Chain hash mismatch at sequence ${seq}`,
        details: {
          sequence: seq,
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

  if (!proof || !Array.isArray(proof.hash_chain) || proof.hash_chain.length === 0) {
    errors.push({
      code: ErrorCode.INPUT_VALIDATION_FAILED,
      message: "Immutability proof must contain a non-empty hash_chain",
      details: { received: proof ? typeof proof.hash_chain : "null proof" },
    });
    return { valid: false, errors };
  }

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

  if (!Array.isArray(items) || items.length === 0) {
    errors.push({
      code: ErrorCode.INPUT_VALIDATION_FAILED,
      message: "Items must be a non-empty array",
      details: { received: Array.isArray(items) ? "empty array" : typeof items },
    });
    return { valid: false, errors };
  }

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

  // Verify items count matches chain length
  const chain = bundle.immutability_proof.hash_chain;
  if (bundle.items.length !== chain.length) {
    errors.push({
      code: ErrorCode.LENGTH_MISMATCH,
      message: `Items count (${bundle.items.length}) does not match chain length (${chain.length})`,
      details: { items: bundle.items.length, chain: chain.length },
    });
  }

  // Cross-check: chain content_hash, item_id, content_type, sequence should match items
  for (let seq = 0; seq < bundle.items.length && seq < chain.length; seq++) {
    const item = bundle.items[seq];
    const link = chain[seq];

    // Verify item.sequence matches its position
    if (item.sequence !== seq) {
      errors.push({
        code: ErrorCode.SEQUENCE_GAP,
        message: `Item ${seq} has sequence ${item.sequence}, expected ${seq}`,
        details: { sequence: seq, item_sequence: item.sequence },
      });
    }

    if (!safeEqual(item.content_hash, link.content_hash)) {
      errors.push({
        code: ErrorCode.CONTENT_HASH_MISMATCH,
        message: `Item ${seq} content_hash does not match chain link`,
        details: {
          sequence: seq,
          item_hash: item.content_hash,
          chain_hash: link.content_hash,
        },
      });
    }

    // v0.2.0: verify item_id and content_type are bound to the chain
    if (link.item_id !== undefined && !safeEqual(item.item_id, link.item_id)) {
      errors.push({
        code: ErrorCode.CONTENT_HASH_MISMATCH,
        message: `Item ${seq} item_id does not match chain link`,
        details: { sequence: seq, item_id: item.item_id, chain_item_id: link.item_id },
      });
    }

    if (link.content_type !== undefined && !safeEqual(item.content_type, link.content_type)) {
      errors.push({
        code: ErrorCode.CONTENT_HASH_MISMATCH,
        message: `Item ${seq} content_type does not match chain link`,
        details: { sequence: seq, content_type: item.content_type, chain_content_type: link.content_type },
      });
    }
  }

  return { valid: errors.length === 0, errors };
}
