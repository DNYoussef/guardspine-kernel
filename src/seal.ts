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

/** Sentinel value for the first link in a hash chain (no predecessor). */
export const GENESIS_HASH = "genesis";

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

  for (let seq = 0; seq < items.length; seq++) {
    const itemContentHash = computeContentHash(items[seq].content);
    const previousHash = seq === 0 ? GENESIS_HASH : chain[seq - 1].chain_hash;
    const chainInput = `${seq}|${itemContentHash}|${previousHash}`;
    const chainHash = sha256(chainInput);

    chain.push({
      sequence: seq,
      content_hash: itemContentHash,
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

  const sealedItems: EvidenceItem[] = bundle.items.map((item, idx) => ({
    item_id: item.item_id ?? `item-${idx}`,
    content_type: item.content_type ?? "unknown",
    content: (item.content ?? {}) as Record<string, unknown>,
    content_hash: chain[idx].content_hash,
    sequence: idx,
  }));

  return {
    immutabilityProof: {
      hash_chain: chain,
      root_hash: rootHash,
    },
    items: sealedItems,
  };
}
