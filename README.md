# @guardspine/kernel

**The canonical trust anchor for GuardSpine evidence bundles.**

[![npm](https://img.shields.io/npm/v/@guardspine/kernel)](https://www.npmjs.com/package/@guardspine/kernel)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Offline evidence-bundle verification and sealing. Zero runtime dependencies.

This is the **single source of truth** for hash chain computation and bundle verification
in the GuardSpine ecosystem. All other implementations (Python, Go, etc.) MUST produce
byte-identical output to this library.

## Spec Version

**Bundle Format**: v0.2.0 / v0.2.1

All bundles sealed by this library use the v0.2.0 immutability proof format:
- Chain entries link via `previous_hash` -> prior `chain_hash` (not content_hash)
- Version enforcement: bundles must declare `version: "0.2.0"` or `"0.2.1"`
- v0.2.1 adds optional sanitization metadata (PII/secret redaction attestation); the proof format is unchanged from v0.2.0
- Golden vectors in `tests/fixtures/` validate cross-implementation parity
- Legacy proof format (pre-v0.2.0, 3-field chain hash) is deprecated with a console.warn

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

## Hardening (v0.2.1)

The kernel includes several defensive measures added during security audit:

- **HMAC buffer length guard**: `timingSafeEqual` throws on mismatched buffer lengths. The HMAC verification path checks length equality before calling `timingSafeEqual`, returning false on mismatch instead of crashing.
- **Incremental root hash**: `computeRootHash` uses streaming `createHash('sha256').update()` instead of string concatenation, avoiding memory pressure on large chains.
- **Max chain items**: `buildHashChain` rejects inputs exceeding 10,000 items.
- **Input validation**: `sealBundle` validates that each item has `item_id` and `content_type` before processing.
- **Constant-time comparison**: All hash comparisons use a `safeEqual()` wrapper over `timingSafeEqual` to prevent timing side-channels.

## Signature Verification

`verifyBundle` checks optional `signatures[]` on the bundle:

| Algorithm | How It Works |
|-----------|-------------|
| `ed25519` | Verify against Ed25519 public key (PEM or raw base64) |
| `rsa-sha256` | Verify against RSA public key |
| `ecdsa-p256` | Verify against ECDSA P-256 key |
| `hmac-sha256` | Recompute HMAC over canonical bundle content using shared secret |

Pass public keys via `options.publicKeys` (a map of `key_id -> PEM/base64`) and HMAC secrets via `options.hmacSecret`.

## Error Codes

| Code | Description |
|------|-------------|
| `MISSING_REQUIRED_FIELD` | Bundle missing a required top-level field |
| `UNSUPPORTED_VERSION` | Bundle version is not "0.2.0" or "0.2.1" |
| `INPUT_VALIDATION_FAILED` | Items array or proof is empty/malformed |
| `CONTENT_HASH_MISMATCH` | Content hash does not match computed SHA-256 |
| `HASH_CHAIN_BROKEN` | Hash chain entry does not link correctly |
| `ROOT_HASH_MISMATCH` | Root hash does not match recomputed value |
| `SEQUENCE_GAP` | Sequence numbers are not contiguous from 0 |
| `LENGTH_MISMATCH` | Items count does not match chain length |
| `SIGNATURE_INVALID` | Signature verification failed |

## Golden Vectors

The `tests/fixtures/` directory contains golden vector bundles that ALL implementations
must verify identically. Do not modify these fixtures.

## Language Implementations

This TypeScript library is the **canonical reference implementation**. All other language ports MUST produce byte-identical hashes.

| Language | Package | Purpose |
|----------|---------|---------|
| **TypeScript** (this repo) | `@guardspine/kernel` | Reference implementation - used by OpenClaw plugin |
| **Python** | [guardspine-kernel-py](https://github.com/DNYoussef/guardspine-kernel-py) | For Python integrations (FastAPI, scripts, ML pipelines) |

**Cross-language guarantee**: Both implementations use RFC 8785 canonical JSON serialization and produce identical SHA256 hashes for the same input. Golden vector tests in `guardspine-spec` validate parity.

## Related Projects

| Project | Description |
|---------|-------------|
| [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) | Bundle specification, golden vectors, JSON Schema |
| [guardspine-kernel-py](https://github.com/DNYoussef/guardspine-kernel-py) | Python port (byte-identical hashes) |
| [codeguard-action](https://github.com/DNYoussef/codeguard-action) | GitHub Action for CI governance |
| [guardspine-verify](https://github.com/DNYoussef/guardspine-verify) | CLI verification tool |
| [guardspine-openclaw](https://github.com/DNYoussef/guardspine-openclaw) | OpenClaw governance plugin |

## License

Apache-2.0
