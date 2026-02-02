/**
 * Evidence Bundle type definitions for @guardspine/kernel.
 * These types mirror the JSON Schema at evidence-bundle.schema.json.
 */

export interface EvidenceBundle {
  bundle_id: string;
  version: string;
  created_at: string;
  policy_id?: string;
  artifact_id?: string;
  risk_tier?: "L0" | "L1" | "L2" | "L3" | "L4";
  items: EvidenceItem[];
  immutability_proof: ImmutabilityProof;
  signatures?: Signature[];
  metadata?: Record<string, unknown>;
}

export interface EvidenceItem {
  item_id: string;
  content_type: string;
  content: Record<string, unknown> | unknown[];
  content_hash: string;
  sequence: number;
  created_at?: string;
}

export interface ImmutabilityProof {
  hash_chain: HashChainLink[];
  root_hash: string;
}

export interface HashChainLink {
  sequence: number;
  item_id: string;
  content_type: string;
  content_hash: string;
  previous_hash: string;
  chain_hash: string;
}

export interface Signature {
  signature_id: string;
  algorithm: "ed25519" | "rsa-sha256" | "ecdsa-p256" | "hmac-sha256";
  signer_id: string;
  signature_value: string;
  signed_at: string;
  public_key_id?: string;
}

export type HashChain = HashChainLink[];
