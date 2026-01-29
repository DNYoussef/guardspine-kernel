/**
 * Bundle sealing and hash-chain construction for @guardspine/kernel.
 * Uses node:crypto for SHA-256. Zero external dependencies.
 */

import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical.js";
import type {
  EvidenceBundle,
  EvidenceItem,
  HashChain,
  HashChainLink,
  ImmutabilityProof,
} from "./schemas/evidence-bundle.js";

/**
 * Compute SHA-256 of the canonical JSON representation of an object.
 * Returns "sha256:<hex>".
 */
export function computeContentHash(content: object): string {
  const canonical = canonicalJson(content);
  const hash = createHash("sha256").update(canonical, "utf-8").digest("hex");
  return `sha256:${hash}`;
}

/**
 * Internal: compute SHA-256 of a raw string. Returns "sha256:<hex>".
 */
function sha256(data: string): string {
  const hash = createHash("sha256").update(data, "utf-8").digest("hex");
  return `sha256:${hash}`;
}

export interface ChainInput {
  content: object;
  contentType: string;
  contentId: string;
}

/**
 * Build a hash chain from an ordered list of items.
 * Each link's chain_hash = SHA-256(sequence + content_hash + previous_hash).
 */
export function buildHashChain(items: ChainInput[]): HashChain {
  const chain: HashChainLink[] = [];

  for (let i = 0; i < items.length; i++) {
    const contentHash = computeContentHash(items[i].content);
    const previousHash = i === 0 ? "genesis" : chain[i - 1].chain_hash;
    const chainInput = `${i}|${contentHash}|${previousHash}`;
    const chainHash = sha256(chainInput);

    chain.push({
      sequence: i,
      content_hash: contentHash,
      previous_hash: previousHash,
      chain_hash: chainHash,
    });
  }

  return chain;
}

/**
 * Compute the root hash over an entire chain.
 * root_hash = SHA-256(concatenation of all chain_hash values).
 */
export function computeRootHash(chain: HashChain): string {
  const concat = chain.map((link) => link.chain_hash).join("");
  return sha256(concat);
}

export interface SealResult {
  immutabilityProof: ImmutabilityProof;
  items: EvidenceItem[];
}

/**
 * Seal a partial bundle: compute content hashes for each item,
 * build the hash chain, and produce the immutability proof.
 *
 * Expects bundle.items to have at least content, content_type, and item_id set.
 * Fills in content_hash and sequence on each item.
 */
export function sealBundle(
  bundle: Partial<EvidenceBundle> & { items: Partial<EvidenceItem>[] }
): SealResult {
  const chainInputs: ChainInput[] = bundle.items.map((item) => ({
    content: item.content ?? {},
    contentType: item.content_type ?? "unknown",
    contentId: item.item_id ?? "unknown",
  }));

  const chain = buildHashChain(chainInputs);
  const rootHash = computeRootHash(chain);

  const sealedItems: EvidenceItem[] = bundle.items.map((item, i) => ({
    item_id: item.item_id ?? `item-${i}`,
    content_type: item.content_type ?? "unknown",
    content: (item.content ?? {}) as Record<string, unknown>,
    content_hash: chain[i].content_hash,
    sequence: i,
  }));

  return {
    immutabilityProof: {
      hash_chain: chain,
      root_hash: rootHash,
    },
    items: sealedItems,
  };
}
