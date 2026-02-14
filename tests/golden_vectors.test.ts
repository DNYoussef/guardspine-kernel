import { describe, it, expect } from 'vitest';
import { sealBundle } from '../src/index.js';
import fs from 'fs';
import path from 'path';

// Resolve path to golden vectors
// 1. Env var: FIXTURES_DIR
// 2. Fallback: Relative path to guardspine-spec/fixtures/golden-vectors
const FIXTURES_DIR = process.env.FIXTURES_DIR || path.resolve(__dirname, '../../guardspine-spec/fixtures/golden-vectors');
const VECTORS_PATH = path.join(FIXTURES_DIR, 'v0.2.0.json');

describe('Kernel Parity: Golden Vectors (v0.2.0)', () => {
    if (!fs.existsSync(VECTORS_PATH)) {
        console.warn(`[WARN] Golden vectors file not found at ${VECTORS_PATH}. Skipping test.`);
        return;
    }

    const vectors = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf-8'));

    vectors.forEach((testCase: any) => {
        it(`should match golden vector: ${testCase.id}`, () => {
            // 1. Construct input bundle
            // We assume input items are "raw" and need normalization logic similar to the adapter
            // BUT for the kernel test, we want to test the kernel's behavior given specific inputs.
            // The kernel expects items with { item_id, content_type, content }.

            const normalizedItems = testCase.inputs.items.map((item: any, idx: number) => {
                // We replicate the normalization logic described in the vector inputs or implied by the expected output
                // Based on generate-golden.ts:
                return {
                    item_id: `item-${idx}-${item.kind}`,
                    content_type: `guardspine/webhook/${item.kind}`,
                    content: {
                        kind: item.kind,
                        summary: item.summary,
                        url: undefined,
                        content: item.content
                    }
                };
            });

            const bundle = {
                bundle_id: "test-bundle-id",
                version: "0.2.0" as const,
                items: normalizedItems,
                metadata: {
                    artifact_id: 'test-artifact',
                    risk_tier: 'low',
                    scope: 'test:scope',
                    provider: 'test-provider'
                }
            };

            // 2. Run Seal
            // Note: current kernel implementation doesn't use salt, so we ignore testCase.inputs.salt
            const result = sealBundle(bundle);

            // 3. Verify
            const proof = result.immutabilityProof;
            const expected = testCase.expected.immutability_proof;

            // Root Hash
            expect(proof.root_hash).toBe(expected.root_hash);

            // Chain
            expect(proof.hash_chain).toHaveLength(expected.hash_chain.length);
            proof.hash_chain.forEach((link, idx) => {
                const expectedLink = expected.hash_chain[idx];
                expect(link.content_hash).toBe(expectedLink.content_hash);
                expect(link.previous_hash).toBe(expectedLink.previous_hash);
                expect(link.chain_hash).toBe(expectedLink.chain_hash);
            });

            // Items content hash (computed by kernel)
            result.items.forEach((item, idx) => {
                const expectedItem = testCase.expected.items[idx];
                expect(item.content_hash).toBe(expectedItem.content_hash);
            });
        });
    });
});
