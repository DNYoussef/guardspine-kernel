/**
 * Offline bundle verification for @guardspine/kernel.
 * Verifies hash chains, root hashes, and content integrity.
 *
 * Trace: Each verification function returns a VerificationResult
 * with explicit error codes, enabling callers to determine exactly
 * which step failed and why. Decisions are logged via error detail objects.
 */

import { createHash, createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { canonicalJson } from "./canonical.js";
import { ErrorCode } from "./errors.js";
import { GENESIS_HASH } from "./seal.js";
import type { ProofVersion } from "./seal.js";
import type { VerificationError, VerificationResult } from "./errors.js";
import type {
  EvidenceBundle,
  EvidenceItem,
  HashChain,
  ImmutabilityProof,
  Signature,
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

function canonicalBytes(obj: unknown): Buffer {
  return Buffer.from(canonicalJson(obj as object), "utf-8");
}

export interface SignatureVerificationOptions {
  /** Map of public_key_id -> PEM or base64 raw Ed25519 key. */
  publicKeys?: Record<string, string>;
  /** Shared secret for HMAC-SHA256 signatures (if used). */
  hmacSecret?: string;
}

export interface ProofVerificationOptions {
  /** Accepted hash-chain proof versions (default: ["v0.2.0"]). */
  acceptProofVersions?: ProofVersion[];
}

export type BundleVerificationOptions = SignatureVerificationOptions & ProofVerificationOptions;

function ed25519RawToSpkiDer(rawKey: Buffer): Buffer {
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return Buffer.concat([prefix, rawKey]);
}

function resolvePublicKey(
  signature: Signature,
  options: SignatureVerificationOptions | undefined,
): Buffer | null {
  const keyId = signature.public_key_id || "default";
  const key = options?.publicKeys?.[keyId] ?? options?.publicKeys?.default;
  if (!key) {
    return null;
  }

  if (key.startsWith("-----BEGIN")) {
    return Buffer.from(key, "utf-8");
  }

  try {
    const raw = Buffer.from(key, "base64");
    if (raw.length === 32) {
      return ed25519RawToSpkiDer(raw);
    }
  } catch {
    return null;
  }

  return null;
}

export function verifySignatures(
  bundle: EvidenceBundle,
  options?: SignatureVerificationOptions,
): VerificationResult {
  const errors: VerificationError[] = [];
  const signatures = bundle.signatures ?? [];
  if (signatures.length === 0) {
    return { valid: true, errors };
  }

  const bundleCopy = { ...bundle, signatures: undefined } as Record<string, unknown>;
  const content = canonicalBytes(bundleCopy);

  for (const sig of signatures) {
    const signatureValue = sig.signature_value;
    if (!signatureValue) {
      errors.push({
        code: ErrorCode.SIGNATURE_INVALID,
        message: "Signature missing signature_value",
        details: { signature_id: sig.signature_id },
      });
      continue;
    }

    const algo = sig.algorithm;
    if (algo === "hmac-sha256") {
      if (!options?.hmacSecret) {
        errors.push({
          code: ErrorCode.SIGNATURE_INVALID,
          message: "HMAC signature present but no hmacSecret provided",
          details: { signature_id: sig.signature_id },
        });
        continue;
      }
      const expected = createHmac("sha256", options.hmacSecret)
        .update(content)
        .digest("base64");
      const expectedBuf = Buffer.from(expected);
      const actualBuf = Buffer.from(signatureValue);
      if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
        errors.push({
          code: ErrorCode.SIGNATURE_INVALID,
          message: "HMAC signature verification failed",
          details: { signature_id: sig.signature_id },
        });
      }
      continue;
    }

    const key = resolvePublicKey(sig, options);
    if (!key) {
      errors.push({
        code: ErrorCode.SIGNATURE_INVALID,
        message: "No public key available for signature",
        details: { signature_id: sig.signature_id, public_key_id: sig.public_key_id },
      });
      continue;
    }

    const signatureBytes = Buffer.from(signatureValue, "base64");
    let ok = false;
    try {
      const keyObject = key.toString("utf-8").startsWith("-----BEGIN")
        ? createPublicKey(key)
        : createPublicKey({ key, format: "der", type: "spki" });

      if (algo === "ed25519") {
        ok = verify(null, content, keyObject, signatureBytes);
      } else if (algo === "rsa-sha256") {
        ok = verify("sha256", content, keyObject, signatureBytes);
      } else if (algo === "ecdsa-p256") {
        ok = verify("sha256", content, keyObject, signatureBytes);
      } else {
        ok = false;
      }
    } catch {
      ok = false;
    }

    if (!ok) {
      errors.push({
        code: ErrorCode.SIGNATURE_INVALID,
        message: "Signature verification failed",
        details: { signature_id: sig.signature_id, algorithm: sig.algorithm },
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Verify that each link in the chain correctly references the previous link
 * and that the chain_hash is computed correctly.
 *
 * Trace rationale: walks the chain sequentially, checking sequence numbers,
 * previous_hash linkage, and recomputed chain_hash. Any mismatch produces
 * a typed error with the expected vs actual values for audit traceability.
 */
function resolveAcceptedProofVersions(
  options?: ProofVerificationOptions,
): ProofVersion[] {
  const versions = options?.acceptProofVersions;
  if (!versions || versions.length === 0) {
    return ["v0.2.0"];
  }
  if (versions.includes("legacy")) {
    console.warn(
      "guardspine-kernel: accepting 'legacy' proof version is deprecated. Migrate chains to 'v0.2.0'.",
    );
  }
  return versions;
}

function chainHashV020(
  sequence: number,
  itemId: string,
  contentType: string,
  contentHash: string,
  previousHash: string,
): string {
  return sha256(`${sequence}|${itemId}|${contentType}|${contentHash}|${previousHash}`);
}

function chainHashLegacy(
  sequence: number,
  contentHash: string,
  previousHash: string,
): string {
  return sha256(`${sequence}|${contentHash}|${previousHash}`);
}

export function verifyHashChain(
  chain: HashChain,
  options?: ProofVerificationOptions,
): VerificationResult {
  const errors: VerificationError[] = [];
  const acceptedVersions = resolveAcceptedProofVersions(options);

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

    const allowV020 = acceptedVersions.includes("v0.2.0");
    const allowLegacy = acceptedVersions.includes("legacy");
    const hasV020Fields =
      typeof link.item_id === "string" && typeof link.content_type === "string";

    let chainValid = false;

    if (allowV020) {
      if (!hasV020Fields && !allowLegacy) {
        errors.push({
          code: ErrorCode.HASH_CHAIN_BROKEN,
          message: `Chain hash missing item_id/content_type at sequence ${seq}`,
          details: { sequence: seq },
        });
      } else if (hasV020Fields) {
        const expectedV020 = chainHashV020(
          link.sequence,
          link.item_id,
          link.content_type,
          link.content_hash,
          link.previous_hash,
        );
        if (safeEqual(link.chain_hash, expectedV020)) {
          chainValid = true;
        }
      }
    }

    if (!chainValid && allowLegacy) {
      const expectedLegacy = chainHashLegacy(
        link.sequence,
        link.content_hash,
        link.previous_hash,
      );
      if (safeEqual(link.chain_hash, expectedLegacy)) {
        chainValid = true;
      }
    }

    if (!chainValid) {
      const expectedHint = allowV020
        ? "v0.2.0"
        : allowLegacy
          ? "legacy"
          : "none";
      errors.push({
        code: ErrorCode.HASH_CHAIN_BROKEN,
        message: `Chain hash mismatch at sequence ${seq}`,
        details: {
          sequence: seq,
          expected_version: expectedHint,
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

  const h = createHash("sha256");
  for (const link of proof.hash_chain) {
    h.update(link.chain_hash, "utf-8");
  }
  const expected = `sha256:${h.digest("hex")}`;

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
export function verifyBundle(
  bundle: EvidenceBundle,
  options?: BundleVerificationOptions,
): VerificationResult {
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

  // Verify bundle version VALUE (not just presence)
  const SUPPORTED_VERSIONS = ["0.2.0"];
  if (bundle.version && !SUPPORTED_VERSIONS.includes(bundle.version)) {
    errors.push({
      code: ErrorCode.UNSUPPORTED_VERSION,
      message: `Unsupported bundle version: ${bundle.version}. Supported: ${SUPPORTED_VERSIONS.join(", ")}`,
      details: { version: bundle.version, supported: SUPPORTED_VERSIONS },
    });
  }

  // If critical fields missing, return early
  if (!bundle.items || !bundle.immutability_proof) {
    return { valid: false, errors };
  }

  // Verify content hashes
  const contentResult = verifyContentHashes(bundle.items);
  errors.push(...contentResult.errors);

  // Verify hash chain
  const chainResult = verifyHashChain(
    bundle.immutability_proof.hash_chain,
    options,
  );
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

  const sigResult = verifySignatures(bundle, options);
  errors.push(...sigResult.errors);

  return { valid: errors.length === 0, errors };
}
