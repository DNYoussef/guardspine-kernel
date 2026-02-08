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

export type ProofVersion = "v0.2.0" | "legacy";

export interface SealOptions {
  proofVersion?: ProofVersion;
}

function chainHashV020(
  sequence: number,
  itemId: string,
  contentType: string,
  contentHash: string,
  previousHash: string,
): string {
  const chainInput = `${sequence}|${itemId}|${contentType}|${contentHash}|${previousHash}`;
  return sha256(chainInput);
}

function chainHashLegacy(
  sequence: number,
  contentHash: string,
  previousHash: string,
): string {
  const chainInput = `${sequence}|${contentHash}|${previousHash}`;
  return sha256(chainInput);
}

function resolveProofVersion(options?: SealOptions): ProofVersion {
  return options?.proofVersion ?? "v0.2.0";
}

/** Hard ceiling on chain length. No evidence bundle should need more. */
const MAX_CHAIN_ITEMS = 10_000;

/**
 * Build a hash chain from an ordered list of items.
 * Each link's chain_hash depends on proofVersion (v0.2.0 by default).
 */
export function buildHashChain(
  items: ChainInput[],
  options?: SealOptions,
): HashChain {
  if (items.length > MAX_CHAIN_ITEMS) {
    throw new Error(
      `buildHashChain: ${items.length} items exceeds limit of ${MAX_CHAIN_ITEMS}`,
    );
  }
  const chain: HashChainLink[] = [];
  const version = resolveProofVersion(options);

  for (let seq = 0; seq < items.length; seq++) {
    const itemContentHash = computeContentHash(items[seq].content);
    const previousHash = seq === 0 ? GENESIS_HASH : chain[seq - 1].chain_hash;
    const chainHash =
      version === "legacy"
        ? chainHashLegacy(seq, itemContentHash, previousHash)
        : chainHashV020(
          seq,
          items[seq].contentId,
          items[seq].contentType,
          itemContentHash,
          previousHash,
        );

    chain.push({
      sequence: seq,
      item_id: items[seq].contentId,
      content_type: items[seq].contentType,
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
 *
 * Uses incremental hashing: O(1) memory instead of building
 * an intermediate concatenated string. Produces identical output.
 */
export function computeRootHash(chain: HashChain): string {
  const h = createHash("sha256");
  for (const link of chain) {
    h.update(link.chain_hash, "utf-8");
  }
  return `sha256:${h.digest("hex")}`;
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
  bundle: Partial<EvidenceBundle> & { items: Partial<EvidenceItem>[] },
  options?: SealOptions,
): SealResult {
  if (!bundle.items || bundle.items.length === 0) {
    throw new Error("sealBundle: items must be a non-empty array");
  }

  const chainInputs: ChainInput[] = bundle.items.map((item, idx) => {
    if (!item.item_id) {
      throw new Error(`sealBundle: item ${idx} missing item_id`);
    }
    if (!item.content_type) {
      throw new Error(`sealBundle: item ${idx} missing content_type`);
    }
    return {
      content: item.content ?? {},
      contentType: item.content_type,
      contentId: item.item_id,
    };
  });

  const chain = buildHashChain(chainInputs, options);
  const rootHash = computeRootHash(chain);

  const sealedItems: EvidenceItem[] = bundle.items.map((item, idx) => ({
    item_id: item.item_id!,
    content_type: item.content_type!,
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
