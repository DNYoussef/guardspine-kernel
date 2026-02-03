import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import {
  buildHashChain,
  computeRootHash,
  verifyBundle,
} from "../src/index.js";
import type { EvidenceBundle } from "../src/index.js";

function loadFixture(name: string): EvidenceBundle {
  const raw = readFileSync(
    new URL(`./fixtures/${name}`, import.meta.url),
    "utf-8",
  );
  return JSON.parse(raw) as EvidenceBundle;
}

function toChainInputs(bundle: EvidenceBundle) {
  return bundle.items.map((item) => ({
    content: item.content as object,
    contentType: item.content_type,
    contentId: item.item_id,
  }));
}

function assertProofMatchesFixture(bundle: EvidenceBundle) {
  const proof = bundle.immutability_proof;
  const chain = buildHashChain(toChainInputs(bundle), { proofVersion: "v0.2.0" });
  const root = computeRootHash(chain);

  expect(chain).toHaveLength(proof.hash_chain.length);
  for (let i = 0; i < chain.length; i += 1) {
    expect(chain[i].chain_hash).toBe(proof.hash_chain[i].chain_hash);
    expect(chain[i].previous_hash).toBe(proof.hash_chain[i].previous_hash);
    expect(chain[i].content_hash).toBe(proof.hash_chain[i].content_hash);
  }
  expect(root).toBe(proof.root_hash);
}

describe("golden vectors (v0.2.0)", () => {
  it("openclaw-hardening fixture matches kernel proof", () => {
    const bundle = loadFixture("openclaw-hardening.bundle.json");
    assertProofMatchesFixture(bundle);
    const result = verifyBundle(bundle, { acceptProofVersions: ["v0.2.0"] });
    expect(result.valid).toBe(true);
  });

  it("local-council fixture matches kernel proof", () => {
    const bundle = loadFixture("local-council.bundle.json");
    assertProofMatchesFixture(bundle);
    const result = verifyBundle(bundle, { acceptProofVersions: ["v0.2.0"] });
    expect(result.valid).toBe(true);
  });

  it("tampering is detected on golden vector", () => {
    const bundle = loadFixture("local-council.bundle.json");
    bundle.items[0].content = { ...bundle.items[0].content, tampered: true };
    const result = verifyBundle(bundle, { acceptProofVersions: ["v0.2.0"] });
    expect(result.valid).toBe(false);
  });
});
