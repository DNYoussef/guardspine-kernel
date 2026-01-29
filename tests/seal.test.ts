import { describe, it, expect } from "vitest";
import {
  computeContentHash,
  buildHashChain,
  computeRootHash,
  sealBundle,
  canonicalJson,
} from "../src/index.js";

describe("canonicalJson", () => {
  it("sorts object keys lexicographically", () => {
    const result = canonicalJson({ z: 1, a: 2, m: 3 });
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it("produces no whitespace", () => {
    const result = canonicalJson({ foo: [1, 2, { bar: true }] });
    expect(result).not.toMatch(/\s/);
  });

  it("handles nested objects with sorted keys", () => {
    const result = canonicalJson({ b: { d: 1, c: 2 }, a: 0 });
    expect(result).toBe('{"a":0,"b":{"c":2,"d":1}}');
  });

  it("handles null, boolean, and numbers", () => {
    expect(canonicalJson(null)).toBe("null");
    expect(canonicalJson(true)).toBe("true");
    expect(canonicalJson(42)).toBe("42");
    expect(canonicalJson(3.14)).toBe("3.14");
  });

  it("skips undefined values in objects", () => {
    const result = canonicalJson({ a: 1, b: undefined, c: 3 });
    expect(result).toBe('{"a":1,"c":3}');
  });
});

describe("computeContentHash", () => {
  it("returns sha256:<hex> format", () => {
    const hash = computeContentHash({ hello: "world" });
    expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("is deterministic", () => {
    const obj = { foo: "bar", num: 42 };
    const h1 = computeContentHash(obj);
    const h2 = computeContentHash(obj);
    expect(h1).toBe(h2);
  });

  it("produces same hash regardless of key order", () => {
    const h1 = computeContentHash({ a: 1, b: 2 });
    const h2 = computeContentHash({ b: 2, a: 1 });
    expect(h1).toBe(h2);
  });
});

describe("buildHashChain", () => {
  it("builds a chain with correct genesis", () => {
    const chain = buildHashChain([
      { content: { x: 1 }, contentType: "test", contentId: "id-0" },
    ]);
    expect(chain).toHaveLength(1);
    expect(chain[0].sequence).toBe(0);
    expect(chain[0].previous_hash).toBe("genesis");
  });

  it("links items sequentially", () => {
    const chain = buildHashChain([
      { content: { x: 1 }, contentType: "test", contentId: "id-0" },
      { content: { x: 2 }, contentType: "test", contentId: "id-1" },
      { content: { x: 3 }, contentType: "test", contentId: "id-2" },
    ]);
    expect(chain).toHaveLength(3);
    expect(chain[1].previous_hash).toBe(chain[0].chain_hash);
    expect(chain[2].previous_hash).toBe(chain[1].chain_hash);
  });
});

describe("computeRootHash", () => {
  it("returns sha256:<hex> format", () => {
    const chain = buildHashChain([
      { content: { x: 1 }, contentType: "test", contentId: "id-0" },
    ]);
    const root = computeRootHash(chain);
    expect(root).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});

describe("sealBundle", () => {
  it("creates a valid sealed bundle", () => {
    const result = sealBundle({
      items: [
        { item_id: "i1", content_type: "test/a", content: { val: 1 } },
        { item_id: "i2", content_type: "test/b", content: { val: 2 } },
      ],
    });

    expect(result.items).toHaveLength(2);
    expect(result.items[0].content_hash).toMatch(/^sha256:/);
    expect(result.items[0].sequence).toBe(0);
    expect(result.items[1].sequence).toBe(1);

    expect(result.immutabilityProof.hash_chain).toHaveLength(2);
    expect(result.immutabilityProof.root_hash).toMatch(/^sha256:/);
  });

  it("sealed items match chain content hashes", () => {
    const result = sealBundle({
      items: [
        { item_id: "i1", content_type: "test/a", content: { val: 1 } },
      ],
    });

    expect(result.items[0].content_hash).toBe(
      result.immutabilityProof.hash_chain[0].content_hash
    );
  });
});
