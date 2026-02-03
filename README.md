# @guardspine/kernel

**The canonical trust anchor for GuardSpine evidence bundles.**

[![npm](https://img.shields.io/npm/v/@guardspine/kernel)](https://www.npmjs.com/package/@guardspine/kernel)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Offline evidence-bundle verification and sealing. Zero runtime dependencies.

This is the **single source of truth** for hash chain computation and bundle verification
in the GuardSpine ecosystem. All other implementations (Python, Go, etc.) MUST produce
byte-identical output to this library.

## Spec Version

**Bundle Format**: v0.2.0

All bundles sealed by this library use the v0.2.0 immutability proof format:
- Chain entries link via `previous_hash` -> prior `chain_hash` (not content_hash)
- Version enforcement: bundles without `version: "0.2.0"` are rejected
- Golden vectors in `tests/fixtures/` validate cross-implementation parity

## Install

```bash
npm install @guardspine/kernel
```

## Usage

### Seal a bundle

```typescript
import { sealBundle } from "@guardspine/kernel";

const { items, immutabilityProof } = sealBundle({
  items: [
    { item_id: "item-1", content_type: "guardspine/test-result", content: { passed: true, name: "auth-check" } },
    { item_id: "item-2", content_type: "guardspine/lint-result", content: { errors: 0 } },
  ],
});

const bundle = {
  bundle_id: crypto.randomUUID(),
  version: "0.2.0",
  created_at: new Date().toISOString(),
  items,
  immutability_proof: immutabilityProof,
};
```

### Verify a bundle

```typescript
import { verifyBundle } from "@guardspine/kernel";

const result = verifyBundle(bundle);

if (result.valid) {
  console.log("Bundle integrity verified.");
} else {
  for (const err of result.errors) {
    console.error(`[${err.code}] ${err.message}`);
  }
}
```

### Compute a content hash

```typescript
import { computeContentHash } from "@guardspine/kernel";

const hash = computeContentHash({ foo: "bar" });
// => "sha256:..."
```

### Canonical JSON (RFC 8785)

```typescript
import { canonicalJson } from "@guardspine/kernel";

canonicalJson({ z: 1, a: 2 });
// => '{"a":2,"z":1}'
```

## Requirements

- Node.js 18+ (uses `node:crypto`)
- TypeScript 5.4+

## Error Codes

| Code | Description |
|------|-------------|
| `INVALID_ITEMS` | Items array is missing or malformed |
| `MISSING_ITEM_ID` | Item lacks `item_id` field |
| `MISSING_CONTENT_TYPE` | Item lacks `content_type` field |
| `HASH_MISMATCH` | Content hash does not match computed hash |
| `CHAIN_MISMATCH` | Hash chain entry does not link correctly |
| `UNSUPPORTED_VERSION` | Bundle version is not "0.2.0" |

## Golden Vectors

The `tests/fixtures/` directory contains golden vector bundles that ALL implementations
must verify identically. Do not modify these fixtures.

## Related Projects

| Project | Description |
|---------|-------------|
| [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) | Bundle specification |
| [guardspine-verify](https://github.com/DNYoussef/guardspine-verify) | Python CLI verifier |
| [guardspine-kernel-py](https://github.com/DNYoussef/guardspine-kernel-py) | Python bridge |

## License

Apache-2.0
