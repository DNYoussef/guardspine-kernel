import { describe, it, expect } from 'vitest';
import { sealBundle } from '../src/index.js';
import fs from 'fs';
import path from 'path';

// Resolve path to golden vectors
// 1. Env var: FIXTURES_DIR
// 2. Fallback: Relative path to guardspine-spec/fixtures/golden-vectors
const FIXTURES_DIR = process.env.FIXTURES_DIR || path.resolve(__dirname, '../../guardspine-spec/fixtures/golden-vectors');
const VECTORS_PATH = path.join(FIXTURES_DIR, 'v0.2.0.json');

const vectorsAvailable = fs.existsSync(VECTORS_PATH);
if (!vectorsAvailable) {
    console.warn(`[WARN] Golden vectors file not found at ${VECTORS_PATH}. Skipping suite.`);
}

describe.skipIf(!vectorsAvailable)('Kernel Parity: Golden Vectors (v0.2.0)', () => {

    // Load vectors lazily so the file read only happens when the suite runs.
    let vectors: any[];
    function getVectors() {
        if (!vectors) {
            vectors = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf-8'));
        }
        return vectors;
    }

    it('loads golden vectors', () => {
        expect(getVectors().length).toBeGreaterThan(0);
    });

    it.each(
        vectorsAvailable
            ? JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf-8')).map((v: any) => [v.id, v])
            : [['skipped', null]]
    )('should match golden vector: %s', (_id, testCase) => {
        if (!testCase) return;

        const normalizedItems = testCase.inputs.items.map((item: any, idx: number) => {
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

        const result = sealBundle(bundle);

        const proof = result.immutabilityProof;
        const expected = testCase.expected.immutability_proof;

        expect(proof.root_hash).toBe(expected.root_hash);

        expect(proof.hash_chain).toHaveLength(expected.hash_chain.length);
        proof.hash_chain.forEach((link, idx) => {
            const expectedLink = expected.hash_chain[idx];
            expect(link.content_hash).toBe(expectedLink.content_hash);
            expect(link.previous_hash).toBe(expectedLink.previous_hash);
            expect(link.chain_hash).toBe(expectedLink.chain_hash);
        });

        result.items.forEach((item, idx) => {
            const expectedItem = testCase.expected.items[idx];
            expect(item.content_hash).toBe(expectedItem.content_hash);
        });
    });
});
