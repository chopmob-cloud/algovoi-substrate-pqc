import { describe, expect, it } from 'vitest';
import { jcsCanonicalBytes } from '../src/canonical.js';
import {
  generateEd25519SecretKey,
  generateES256SecretKey,
  generateFalcon1024Keypair,
  generateMLDSA65Keypair,
  signEd25519,
  signES256,
  signFalcon1024,
  signMLDSA65,
} from '../src/sign.js';
import { UnknownSignatureAlgorithmError } from '../src/registry.js';
import {
  verifyArtefact,
  verifyEd25519,
  verifyES256,
  verifyFalcon1024,
  verifyMLDSA65,
  verifySignature,
} from '../src/verify.js';
import { buildConvergenceArtefact } from '../src/proof.js';

const payload = {
  amount: { currency: 'USD', minor_units: 4995 },
  issuer: 'did:web:wallet.example.org',
  merchant: 'did:web:merchant.example.com',
  nonce: '0x7b5ce8a4f1b9a4d2',
};

describe('Round-trip sign/verify (all four schemes)', () => {
  it('ES256 round-trips', () => {
    const sk = generateES256SecretKey();
    const sig = signES256(payload, sk);
    const result = verifyES256(jcsCanonicalBytes(payload), sig as unknown as Record<string, unknown>);
    expect(result.ok, result.detail).toBe(true);
  });

  it('Ed25519 round-trips', () => {
    const sk = generateEd25519SecretKey();
    const sig = signEd25519(payload, sk);
    const result = verifyEd25519(
      jcsCanonicalBytes(payload),
      sig as unknown as Record<string, unknown>,
    );
    expect(result.ok, result.detail).toBe(true);
  });

  it('Falcon-1024 round-trips', () => {
    const { publicKey, secretKey } = generateFalcon1024Keypair();
    const sig = signFalcon1024(payload, secretKey, publicKey);
    const result = verifyFalcon1024(
      jcsCanonicalBytes(payload),
      sig as unknown as Record<string, unknown>,
    );
    expect(result.ok, result.detail).toBe(true);
  });

  it('ML-DSA-65 round-trips', () => {
    const { publicKey, secretKey } = generateMLDSA65Keypair();
    const sig = signMLDSA65(payload, secretKey, publicKey);
    const result = verifyMLDSA65(
      jcsCanonicalBytes(payload),
      sig as unknown as Record<string, unknown>,
    );
    expect(result.ok, result.detail).toBe(true);
  });

  it('builds a 4-scheme convergence artefact and verifies end-to-end', () => {
    const es = generateES256SecretKey();
    const ed = generateEd25519SecretKey();
    const f = generateFalcon1024Keypair();
    const m = generateMLDSA65Keypair();

    const signatures = {
      ES256: signES256(payload, es) as unknown as Record<string, unknown>,
      Ed25519: signEd25519(payload, ed) as unknown as Record<string, unknown>,
      'Falcon-1024': signFalcon1024(payload, f.secretKey, f.publicKey) as unknown as Record<
        string,
        unknown
      >,
      'ML-DSA-65': signMLDSA65(payload, m.secretKey, m.publicKey) as unknown as Record<
        string,
        unknown
      >,
    };

    const artefact = buildConvergenceArtefact(payload, signatures, {
      artefactId: 'test-convergence-v0',
    });

    const result = verifyArtefact(artefact as unknown as Parameters<typeof verifyArtefact>[0]);
    expect(
      result.canonicalShaOk,
      `expected ${result.canonicalShaExpected}, got ${result.canonicalShaRecomputed}`,
    ).toBe(true);
    expect(result.signatures.length).toBe(4);
    for (const s of result.signatures) {
      expect(s.ok, `${s.algorithm} failed: ${s.detail}`).toBe(true);
    }
  });

  it('unknown algorithm fails closed', () => {
    const canonical = jcsCanonicalBytes(payload);
    expect(() =>
      verifySignature(canonical, 'NotAReal-Scheme', { signature_b64: 'AAA=' }),
    ).toThrow(UnknownSignatureAlgorithmError);
  });
});
