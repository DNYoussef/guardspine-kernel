/**
 * Evidence Bundle type definitions for @guardspine/kernel.
 * These types mirror the JSON Schema at evidence-bundle.schema.json.
 */

export interface EvidenceBundle {
  bundle_id: string;
  version: string;
  created_at: string;
  policy_id?: string;
  items: EvidenceItem[];
  immutability_proof: ImmutabilityProof;
  metadata?: Record<string, unknown>;
}

export interface EvidenceItem {
  item_id: string;
  content_type: string;
  content: Record<string, unknown>;
  content_hash: string;
  sequence: number;
}

export interface ImmutabilityProof {
  hash_chain: HashChainLink[];
  root_hash: string;
  signature?: string;
}

export interface HashChainLink {
  sequence: number;
  content_hash: string;
  previous_hash: string;
  chain_hash: string;
}

export type HashChain = HashChainLink[];
