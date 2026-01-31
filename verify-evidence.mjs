import { readFileSync, writeFileSync } from 'fs';
import { verifyBundle } from './dist/index.js';

const bundle = JSON.parse(readFileSync('D:/Projects/GuardSpine/evidence-pack/08-integration/sealed-bundle.json', 'utf-8'));

const pos = verifyBundle(bundle);
const posResult = { test: 'positive', valid: pos.valid, errors: pos.errors.length };

const tampered = JSON.parse(JSON.stringify(bundle));
tampered.items[0].content.total_violations = 999999;
const neg = verifyBundle(tampered);
const negResult = { test: 'negative_tampered', valid: neg.valid, errors: neg.errors.length, firstErrorCode: neg.errors[0]?.code };

const output = { positive_verification: posResult, negative_verification: negResult, proof: "If positive=true AND negative=false, cryptographic integrity is proven" };
writeFileSync('D:/Projects/GuardSpine/evidence-pack/08-integration/verification-proof.json', JSON.stringify(output, null, 2));
console.log(JSON.stringify(output, null, 2));
