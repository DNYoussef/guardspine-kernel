import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { verifyBundle, sealBundle, ErrorCode } from "../src/index.js";
import type { EvidenceBundle } from "../src/index.js";
import { canonicalJson } from "../src/canonical.js";

function makeBundle(): EvidenceBundle {
  const result = sealBundle({
    items: [
      { item_id: "i1", content_type: "test/a", content: { val: 1 } },
      { item_id: "i2", content_type: "test/b", content: { val: 2 } },
    ],
  });
  return {
    bundle_id: "b1",
    version: "0.2.0",
    created_at: "2026-06-24T00:00:00Z",
    items: result.items,
    immutability_proof: result.immutabilityProof,
  };
}

function fingerprint(pub: KeyObject): string {
  const der = pub.export({ type: "spki", format: "der" }) as Buffer;
  return `sha256:${createHash("sha256").update(der).digest("hex")}`;
}

function signWith(bundle: EvidenceBundle, priv: KeyObject, pub: KeyObject, claimedKeyId?: string) {
  const content = Buffer.from(canonicalJson({ ...bundle, signatures: undefined }), "utf-8");
  const sigBytes = sign(null, content, priv);
  const pem = (pub.export({ type: "spki", format: "pem" }) as string).toString();
  return {
    ...bundle,
    signatures: [
      {
        signature_id: "s1",
        algorithm: "ed25519",
        signer_id: "x",
        signature_value: sigBytes.toString("base64"),
        public_key_id: claimedKeyId ?? fingerprint(pub),
        public_key: pem,
        signed_at: "2026-06-24T00:00:00Z",
      },
    ],
  } as EvidenceBundle;
}

function genKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { priv: privateKey, pub: publicKey, fp: fingerprint(publicKey) };
}

describe("anti-forgery parity", () => {
  it("legit signed verifies against a trusted fingerprint (require)", () => {
    const k = genKey();
    const b = signWith(makeBundle(), k.priv, k.pub);
    const r = verifyBundle(b, { trustedFingerprints: [k.fp], requireSignature: true });
    expect(r.valid).toBe(true);
  });

  it("legit signed verifies via external publicKeys (require)", () => {
    const k = genKey();
    const b = signWith(makeBundle(), k.priv, k.pub);
    const pem = (k.pub.export({ type: "spki", format: "pem" }) as string).toString();
    const r = verifyBundle(b, { publicKeys: { [k.fp]: pem }, requireSignature: true });
    expect(r.valid).toBe(true);
  });

  it("unsigned + requireSignature is rejected", () => {
    const r = verifyBundle(makeBundle(), { requireSignature: true });
    expect(r.valid).toBe(false);
    expect(r.errors.map((e) => e.code)).toContain(ErrorCode.SIGNATURE_REQUIRED);
  });

  it("trustedFingerprints alone enforces (unsigned rejected)", () => {
    const k = genKey();
    const r = verifyBundle(makeBundle(), { trustedFingerprints: [k.fp] });
    expect(r.valid).toBe(false);
  });

  it("re-sign with attacker key is rejected (untrusted fingerprint)", () => {
    const legit = genKey();
    const attacker = genKey();
    const b = signWith(makeBundle(), attacker.priv, attacker.pub);
    const r = verifyBundle(b, { trustedFingerprints: [legit.fp], requireSignature: true });
    expect(r.valid).toBe(false);
  });

  it("stale signature over mutated bundle is rejected", () => {
    const k = genKey();
    const b = signWith(makeBundle(), k.priv, k.pub);
    (b as { created_at: string }).created_at = "2099-01-01T00:00:00Z"; // mutate top-level
    const r = verifyBundle(b, { trustedFingerprints: [k.fp], requireSignature: true });
    expect(r.valid).toBe(false);
  });

  it("key_id spoof is rejected (fingerprint recomputed from key bytes)", () => {
    const legit = genKey();
    const attacker = genKey();
    // attacker signs with own key but claims the legit fingerprint as public_key_id
    const b = signWith(makeBundle(), attacker.priv, attacker.pub, legit.fp);
    const r = verifyBundle(b, { trustedFingerprints: [legit.fp], requireSignature: true });
    expect(r.valid).toBe(false);
  });

  it("backward compatible: plain valid bundle still verifies with no options", () => {
    const r = verifyBundle(makeBundle());
    expect(r.valid).toBe(true);
  });

  it("publicKeys alone activates the gate (unsigned rejected)", () => {
    const k = genKey();
    const pem = (k.pub.export({ type: "spki", format: "pem" }) as string).toString();
    const r = verifyBundle(makeBundle(), { publicKeys: { [k.fp]: pem } });
    expect(r.valid).toBe(false);
    expect(r.errors.map((e) => e.code)).toContain(ErrorCode.SIGNATURE_REQUIRED);
  });

  it("junk extra signature cannot DoS a valid trusted bundle", () => {
    const legit = genKey();
    const attacker = genKey();
    const b = signWith(makeBundle(), legit.priv, legit.pub);
    const attackerPem = (attacker.pub.export({ type: "spki", format: "pem" }) as string).toString();
    // append an untrusted junk signature after the valid trusted one
    (b.signatures as unknown[]).push({
      signature_id: "junk",
      algorithm: "ed25519",
      signer_id: "attacker",
      signature_value: Buffer.from("not-a-real-signature").toString("base64"),
      public_key_id: attacker.fp,
      public_key: attackerPem,
      signed_at: "2026-06-24T00:00:00Z",
    });
    const r = verifyBundle(b, { trustedFingerprints: [legit.fp], requireSignature: true });
    expect(r.valid).toBe(true);
  });

  it("a valid trusted signature buried after 1500 junk signatures still verifies", () => {
    const legit = genKey();
    const attacker = genKey();
    const attackerPem = (attacker.pub.export({ type: "spki", format: "pem" }) as string).toString();
    const b = signWith(makeBundle(), legit.priv, legit.pub);
    const legitSig = b.signatures![0];
    const junk = Array.from({ length: 1500 }, (_, i) => ({
      signature_id: `junk${i}`,
      algorithm: "ed25519",
      signer_id: "attacker",
      signature_value: Buffer.from(`junk${i}`).toString("base64"),
      public_key_id: attacker.fp,
      public_key: attackerPem,
      signed_at: "2026-06-24T00:00:00Z",
    }));
    b.signatures = [...junk, legitSig] as typeof b.signatures; // legit one is LAST
    const r = verifyBundle(b, { trustedFingerprints: [legit.fp], requireSignature: true });
    expect(r.valid).toBe(true);
  });

  it("bogus signatures embedding the LEGIT public key cannot starve the real one", () => {
    // Trusted fingerprints are public: an attacker can mint many trusted-fp
    // candidates with invalid signatures. The real valid signature (last) must
    // still be found -- no verify cap may break before reaching it.
    const legit = genKey();
    const legitPem = (legit.pub.export({ type: "spki", format: "pem" }) as string).toString();
    const b = signWith(makeBundle(), legit.priv, legit.pub);
    const realSig = b.signatures![0];
    const bogus = Array.from({ length: 70 }, (_, i) => ({
      signature_id: `bogus${i}`,
      algorithm: "ed25519",
      signer_id: "attacker",
      signature_value: Buffer.from(`bogus${i}`).toString("base64"),
      public_key_id: legit.fp,
      public_key: legitPem, // LEGIT key (public) -> passes the fingerprint filter
      signed_at: "2026-06-24T00:00:00Z",
    }));
    b.signatures = [...bogus, realSig] as typeof b.signatures;
    const r = verifyBundle(b, { trustedFingerprints: [legit.fp], requireSignature: true });
    expect(r.valid).toBe(true);
  });

  it("algorithm-label mismatch is rejected", () => {
    const k = genKey();
    const b = signWith(makeBundle(), k.priv, k.pub);
    (b.signatures![0] as { algorithm: string }).algorithm = "ecdsa-p256"; // ed25519 sig mislabeled
    const r = verifyBundle(b, { trustedFingerprints: [k.fp], requireSignature: true });
    expect(r.valid).toBe(false);
  });
});
