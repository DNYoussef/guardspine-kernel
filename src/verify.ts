// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 GuardSpine, Inc.
// Licensed under the Business Source License 1.1. See LICENSE for terms.
// Change License: Apache-2.0. Change Date: see LICENSE.
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

function sha256Bytes(buf: Buffer): string {
  return `sha256:${createHash("sha256").update(buf).digest("hex")}`;
}

/** Bind the declared algorithm to the actual key type/curve (no label confusion). */
function keyMatchesAlgo(keyObj: ReturnType<typeof createPublicKey>, algo: string): boolean {
  const t = keyObj.asymmetricKeyType;
  if (algo === "ed25519") return t === "ed25519";
  if (algo === "rsa-sha256") return t === "rsa";
  if (algo === "ecdsa-p256") {
    return t === "ec" && keyObj.asymmetricKeyDetails?.namedCurve === "prime256v1";
  }
  return false;
}

function contentHash(content: unknown): string {
  return sha256(canonicalJson(content));
}

function canonicalBytes(obj: unknown): Buffer {
  return Buffer.from(canonicalJson(obj as object), "utf-8");
}

export interface SignatureVerificationOptions {
  /** Map of public_key_id -> PEM or base64 raw Ed25519 key (external trust). */
  publicKeys?: Record<string, string>;
  /** Shared secret for HMAC-SHA256 signatures (if used). */
  hmacSecret?: string;
  /**
   * Allow-listed "sha256:<hex>" SPKI fingerprints. A signature whose embedded
   * public_key recomputes to one of these is trusted (self-contained bundles).
   */
  trustedFingerprints?: string[];
  /**
   * Anti-forgery: when true (or when trustedFingerprints is non-empty), the
   * bundle MUST carry >=1 asymmetric signature that is cryptographically valid
   * AND trusted (key_id in publicKeys, or embedded key whose fingerprint is
   * allow-listed). HMAC never counts.
   */
  requireSignature?: boolean;
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
  const keyId = signature.public_key_id;
  // Prefer a caller-supplied (externally trusted) key; otherwise fall back to the
  // key embedded in the signature. This function only attests CRYPTO validity --
  // trust (fingerprint pinning / key_id allow-listing) is enforced separately by
  // countTrustedValidSignatures + requireSignature in verifyBundle.
  const key =
    (keyId ? options?.publicKeys?.[keyId] : undefined) ??
    (signature as { public_key?: string }).public_key;
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
  if (!Array.isArray(signatures) || signatures.length === 0) {
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

      if (!keyMatchesAlgo(keyObject, algo)) {
        ok = false; // algorithm label does not match the actual key type/curve
      } else if (algo === "ed25519") {
        ok = verify(null, content, keyObject, signatureBytes);
      } else {
        ok = verify("sha256", content, keyObject, signatureBytes);
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

function loadPublicKeyDer(keyMaterial: string): { keyObj: ReturnType<typeof createPublicKey>; der: Buffer } {
  let keyObj;
  if (keyMaterial.startsWith("-----BEGIN")) {
    keyObj = createPublicKey(keyMaterial);
  } else {
    const raw = Buffer.from(keyMaterial, "base64");
    const der = raw.length === 32 ? ed25519RawToSpkiDer(raw) : raw;
    keyObj = createPublicKey({ key: der, format: "der", type: "spki" });
  }
  const der = keyObj.export({ type: "spki", format: "der" }) as Buffer;
  return { keyObj, der };
}

/**
 * Count asymmetric signatures that are BOTH cryptographically valid over the
 * canonical payload AND trusted. Trust = key_id in publicKeys (external, verified
 * against the CALLER's key) OR the signer key's fingerprint, RECOMPUTED from the
 * embedded public_key bytes (never the claimed public_key_id), is allow-listed.
 * HMAC never counts. Trust-filtered before crypto; short-circuits on first hit.
 */
function countTrustedValidSignatures(
  bundle: EvidenceBundle,
  options: SignatureVerificationOptions | undefined,
): number {
  const sigs = (bundle.signatures ?? []) as Signature[];
  if (!Array.isArray(sigs) || sigs.length === 0) {
    return 0;
  }
  const content = canonicalBytes({ ...bundle, signatures: undefined });
  const tf = new Set(options?.trustedFingerprints ?? []);
  const tk = options?.publicKeys ?? {};
  // Scan ALL signatures, and never cap crypto on TRUSTED candidates: a trusted
  // public key is public and copyable, so an attacker can mint many
  // trusted-fingerprint candidates with bogus signatures -- any total/verify cap
  // would let them STARVE the real valid one. Untrusted sigs (fingerprint not
  // pinned / key_id not supplied) are cheap-skipped before any crypto, so junk
  // cannot force crypto work. ed25519/ECDSA/RSA verify is cheap; return on first
  // trusted-valid signature.
  for (const sig of sigs) {
    if (!sig || typeof sig !== "object") continue;
    const algo = sig.algorithm;
    if (algo !== "ed25519" && algo !== "rsa-sha256" && algo !== "ecdsa-p256") continue;
    const sigval = sig.signature_value;
    if (!sigval) continue;
    const keyId = sig.public_key_id;
    let keyMaterial: string | undefined;
    let trusted = false;
    if (keyId && tk[keyId]) {
      keyMaterial = tk[keyId];
      trusted = true;
    } else if ((sig as { public_key?: string }).public_key) {
      keyMaterial = (sig as { public_key?: string }).public_key;
      trusted = false;
    } else {
      continue;
    }
    let keyObj: ReturnType<typeof createPublicKey>;
    let der: Buffer;
    try {
      ({ keyObj, der } = loadPublicKeyDer(keyMaterial as string));
    } catch {
      continue;
    }
    if (!trusted && !tf.has(sha256Bytes(der))) {
      continue; // embedded key not fingerprint-pinned -> untrusted
    }
    if (!keyMatchesAlgo(keyObj, algo)) {
      continue; // algorithm label does not match the actual key type/curve
    }
    try {
      const signatureBytes = Buffer.from(sigval, "base64");
      const ok =
        algo === "ed25519"
          ? verify(null, content, keyObj, signatureBytes)
          : verify("sha256", content, keyObj, signatureBytes);
      if (ok) return 1;
    } catch {
      // fall through
    }
  }
  return 0;
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

  // Verify bundle version VALUE (not just presence).
  // v0.2.1 adds optional sanitization metadata; proof format is unchanged from v0.2.0.
  const SUPPORTED_VERSIONS = ["0.2.0", "0.2.1"];
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

  // Signature handling. A trust anchor (requireSignature, trustedFingerprints, OR
  // a non-empty publicKeys map) activates the ANTI-FORGERY gate: acceptance is
  // based on >=1 cryptographically valid signature from a trusted key. Untrusted
  // or junk extra signatures are ignored (they cannot DoS a valid trusted bundle,
  // since signatures are excluded from the signed payload). HMAC never counts.
  const wantsAsymTrust =
    options?.requireSignature === true ||
    (options?.trustedFingerprints?.length ?? 0) > 0 ||
    (options?.publicKeys ? Object.keys(options.publicKeys).length > 0 : false);
  if (wantsAsymTrust) {
    if (countTrustedValidSignatures(bundle, options) === 0) {
      errors.push({
        code: ErrorCode.SIGNATURE_REQUIRED,
        message:
          "no valid signature from a trusted key (absent, untrusted, forged, or HMAC-only)",
        details: {},
      });
    }
  } else if (options?.hmacSecret) {
    // Shared-secret integrity (NOT anti-forgery): verify present signatures.
    errors.push(...verifySignatures(bundle, options).errors);
  }

  return { valid: errors.length === 0, errors };
}
