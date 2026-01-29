# @guardspine/kernel

Offline evidence-bundle verification and sealing. Zero runtime dependencies.

This is the trust anchor for the GuardSpine ecosystem. It works standalone
without any backend service.

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
  version: "0.1.0",
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

## License

Apache-2.0
