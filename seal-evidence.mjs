import { readFileSync, writeFileSync, readdirSync } from 'fs';
import { sealBundle } from './dist/index.js';
import { createHash } from 'crypto';

const rubricResults = JSON.parse(readFileSync('D:/Projects/GuardSpine/evidence-pack/04-code-guard/rubric-scores.json', 'utf-8'));
const items = [];

items.push({
  item_id: 'audit-meta',
  content_type: 'guardspine/audit-metadata',
  content: {
    tool: 'codeguard', version: '0.3.0', target: rubricResults.target,
    timestamp: rubricResults.timestamp, files_scanned: rubricResults.files_scanned,
    total_violations: rubricResults.total_violations,
  },
});

for (const r of rubricResults.rubric_results) {
  items.push({
    item_id: `rubric-${r.rubric}`,
    content_type: 'guardspine/rubric-result',
    content: { rubric: r.rubric, rules_count: r.rules_count, violations_found: r.violations_found, violations: r.violations || [], error: r.error || null },
  });
}

const srcDir = 'D:/Projects/guardspine-kernel/src';
const sourceHashes = {};
for (const f of readdirSync(srcDir).filter(f => f.endsWith('.ts'))) {
  sourceHashes[f] = 'sha256:' + createHash('sha256').update(readFileSync(`${srcDir}/${f}`)).digest('hex');
}
items.push({ item_id: 'source-provenance', content_type: 'guardspine/source-hashes', content: sourceHashes });

const result = sealBundle({ items });
const bundle = {
  bundle_id: `dogfood-pack-${Date.now()}`, version: '1.0.0',
  created_at: new Date().toISOString(), source: 'guardspine-dogfood-pack',
  items: result.items, immutability_proof: result.immutabilityProof,
};

writeFileSync('D:/Projects/GuardSpine/evidence-pack/08-integration/sealed-bundle.json', JSON.stringify(bundle, null, 2));
console.log(`Sealed ${items.length} items. Root hash: ${bundle.immutability_proof.root_hash}`);
