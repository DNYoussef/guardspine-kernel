import { describe, it, expect } from "vitest";
import {
  verifyBundle,
  verifyHashChain,
  verifyContentHashes,
  verifyRootHash,
  sealBundle,
  ErrorCode,
} from "../src/index.js";
import type { EvidenceBundle } from "../src/index.js";

function makeValidBundle(): EvidenceBundle {
  const result = sealBundle({
    items: [
      { item_id: "i1", content_type: "test/a", content: { val: 1 } },
      { item_id: "i2", content_type: "test/b", content: { val: 2 } },
      { item_id: "i3", content_type: "test/c", content: { val: 3 } },
    ],
  });

  return {
    bundle_id: "test-bundle-001",
    version: "0.2.0",
    created_at: "2026-01-29T00:00:00Z",
    items: result.items,
    immutability_proof: result.immutabilityProof,
  };
}

describe("verifyBundle", () => {
  it("passes for a valid bundle", () => {
    const bundle = makeValidBundle();
    const result = verifyBundle(bundle);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("detects content hash mismatch (tampered content)", () => {
    const bundle = makeValidBundle();
    // Tamper with an item's content without updating hash
    bundle.items[1].content = { val: 999 };

    const result = verifyBundle(bundle);
    expect(result.valid).toBe(false);
    const codes = result.errors.map((e) => e.code);
    expect(codes).toContain(ErrorCode.CONTENT_HASH_MISMATCH);
  });

  it("detects broken chain (wrong previous_hash)", () => {
    const bundle = makeValidBundle();
    // Break the chain by modifying a previous_hash
    bundle.immutability_proof.hash_chain[1].previous_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    const result = verifyBundle(bundle);
    expect(result.valid).toBe(false);
    const codes = result.errors.map((e) => e.code);
    expect(codes).toContain(ErrorCode.HASH_CHAIN_BROKEN);
  });

  it("detects missing required fields", () => {
    const bundle = makeValidBundle();
    // Remove a required field
    const partial = { ...bundle } as Record<string, unknown>;
    delete partial["bundle_id"];

    const result = verifyBundle(partial as unknown as EvidenceBundle);
    expect(result.valid).toBe(false);
    const codes = result.errors.map((e) => e.code);
    expect(codes).toContain(ErrorCode.MISSING_REQUIRED_FIELD);
  });

  it("detects root hash mismatch", () => {
    const bundle = makeValidBundle();
    bundle.immutability_proof.root_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    const result = verifyBundle(bundle);
    expect(result.valid).toBe(false);
    const codes = result.errors.map((e) => e.code);
    expect(codes).toContain(ErrorCode.ROOT_HASH_MISMATCH);
  });
});

describe("verifyHashChain", () => {
  it("passes for a valid chain", () => {
    const bundle = makeValidBundle();
    const result = verifyHashChain(bundle.immutability_proof.hash_chain);
    expect(result.valid).toBe(true);
  });

  it("detects sequence gap", () => {
    const bundle = makeValidBundle();
    // Set wrong sequence number
    bundle.immutability_proof.hash_chain[2].sequence = 5;

    const result = verifyHashChain(bundle.immutability_proof.hash_chain);
    expect(result.valid).toBe(false);
    expect(result.errors[0].code).toBe(ErrorCode.SEQUENCE_GAP);
  });
});

describe("verifyContentHashes", () => {
  it("passes for valid items", () => {
    const bundle = makeValidBundle();
    const result = verifyContentHashes(bundle.items);
    expect(result.valid).toBe(true);
  });
});

describe("verifyRootHash", () => {
  it("passes for valid proof", () => {
    const bundle = makeValidBundle();
    const result = verifyRootHash(bundle.immutability_proof);
    expect(result.valid).toBe(true);
  });
});
