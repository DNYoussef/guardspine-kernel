import { sealBundle, verifyBundle } from './dist/index.js';

const result = sealBundle({
  items: [
    { item_id: 'finding-001', content_type: 'audit/finding', content: { rule: 'CON-001', severity: 'low', message: 'Connascence of Name detected' } },
    { item_id: 'finding-002', content_type: 'audit/finding', content: { rule: 'NASA-003', severity: 'medium', message: 'Function exceeds 60 lines' } },
    { item_id: 'meta-001', content_type: 'audit/metadata', content: { tool: 'codeguard', version: '0.3.0', target: 'guardspine-kernel/src', timestamp: new Date().toISOString() } },
  ],
});

const bundle = {
  bundle_id: 'evidence-pack-proof-001',
  version: '1.0.0',
  created_at: new Date().toISOString(),
  items: result.items,
  immutability_proof: result.immutabilityProof,
};

const validResult = verifyBundle(bundle);
console.log('=== POSITIVE VERIFICATION ===');
console.log(JSON.stringify({ valid: validResult.valid, errorCount: validResult.errors.length, rootHash: bundle.immutability_proof.root_hash }, null, 2));

const tampered = JSON.parse(JSON.stringify(bundle));
tampered.items[0].content.severity = 'critical';
const invalidResult = verifyBundle(tampered);
console.log('=== NEGATIVE VERIFICATION (tampered) ===');
console.log(JSON.stringify({ valid: invalidResult.valid, errorCount: invalidResult.errors.length, firstError: invalidResult.errors[0]?.code }, null, 2));

console.log('=== SEALED BUNDLE ===');
console.log(JSON.stringify(bundle, null, 2));
