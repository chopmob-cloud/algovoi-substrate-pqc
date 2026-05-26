import { describe, expect, it } from 'vitest';
import {
  KNOWN_SIGNATURE_ALGORITHMS,
  SignatureAlgorithmFamily,
  UnknownSignatureAlgorithmError,
  lookupSignatureAlgorithm,
} from '../src/registry.js';

describe('signature_algorithm registry', () => {
  it('contains 12 recommended values', () => {
    expect(KNOWN_SIGNATURE_ALGORITHMS.size).toBe(12);
  });

  it.each([
    ['ECDSA', SignatureAlgorithmFamily.CLASSICAL],
    ['ES256', SignatureAlgorithmFamily.CLASSICAL],
    ['ES256K', SignatureAlgorithmFamily.CLASSICAL],
    ['Ed25519', SignatureAlgorithmFamily.CLASSICAL],
    ['ML-DSA-44', SignatureAlgorithmFamily.PQC],
    ['ML-DSA-65', SignatureAlgorithmFamily.PQC],
    ['ML-DSA-87', SignatureAlgorithmFamily.PQC],
    ['Falcon-512', SignatureAlgorithmFamily.PQC],
    ['Falcon-1024', SignatureAlgorithmFamily.PQC],
    ['SLH-DSA-SHA2-128s', SignatureAlgorithmFamily.PQC_STATELESS_HASH],
    ['HMAC-SHA-256', SignatureAlgorithmFamily.HMAC],
    ['HMAC-SHA-384', SignatureAlgorithmFamily.HMAC],
  ] as const)('looks up %s as %s', (identifier, family) => {
    const rec = lookupSignatureAlgorithm(identifier);
    expect(rec.identifier).toBe(identifier);
    expect(rec.family).toBe(family);
  });

  it('lookup is case-sensitive per RFC 7517 §4.1', () => {
    expect(() => lookupSignatureAlgorithm('Ed25519')).not.toThrow();
    expect(() => lookupSignatureAlgorithm('ed25519')).toThrow(UnknownSignatureAlgorithmError);
  });

  it('unknown identifier fails closed', () => {
    expect(() => lookupSignatureAlgorithm('NotAnAlgorithm-9999')).toThrow(
      UnknownSignatureAlgorithmError,
    );
  });
});
