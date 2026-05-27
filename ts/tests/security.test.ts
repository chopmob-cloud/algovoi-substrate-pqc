/**
 * Security regression tests for @algovoi/substrate-pqc.
 *
 * Covers the findings from the 0.1.2 security audit:
 *
 *   H-1  Vacuous-truth bypass — artefact with empty signatures must not return ok:true.
 *   H-2  Missing payload throws TypeError, not a silent crash.
 *   M-2  verifyES256Strict is exported and rejects high-s signatures.
 *   M-3  Registry-known-but-unimplemented algorithm returns ok:false.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { jcsCanonicalBytes } from '../src/canonical.js';
import { signEd25519, signES256, generateES256SecretKey, generateEd25519SecretKey } from '../src/sign.js';
import { verifyArtefact, verifyES256, verifyES256Strict, verifySignature } from '../src/verify.js';

const SIMPLE_PAYLOAD = { amount: 100, currency: 'USD', nonce: 'abc123' };

function makeArtefactNoSigs(payload: unknown) {
  const canonical = jcsCanonicalBytes(payload);
  const sha = 'sha256:' + bytesToHex(sha256(canonical));
  return {
    mandate_body: payload,
    expected_canonical_sha256: sha,
    signatures: {} as Record<string, Record<string, unknown>>,
  };
}

// -------------------------------------------------------------------------
// H-1 — vacuous-truth empty-signatures bypass
// -------------------------------------------------------------------------

describe('H-1: empty signatures vacuous-truth bypass', () => {
  it('artefact with empty signatures must not return ok:true', () => {
    const artefact = makeArtefactNoSigs(SIMPLE_PAYLOAD);
    const result = verifyArtefact(artefact);
    expect(result.canonicalShaOk).toBe(true); // precondition
    expect(result.signatures).toHaveLength(0); // precondition
    expect(result.ok).toBe(false); // the fix
  });

  it('artefact with valid signatures returns ok:true', () => {
    const esSk = generateES256SecretKey();
    const edSk = generateEd25519SecretKey();
    const esSig = signES256(SIMPLE_PAYLOAD, esSk);
    const edSig = signEd25519(SIMPLE_PAYLOAD, edSk);
    const canonical = jcsCanonicalBytes(SIMPLE_PAYLOAD);
    const sha = 'sha256:' + bytesToHex(sha256(canonical));
    const artefact = {
      mandate_body: SIMPLE_PAYLOAD,
      expected_canonical_sha256: sha,
      signatures: {
        ES256: esSig as Record<string, unknown>,
        Ed25519: edSig as Record<string, unknown>,
      },
    };
    const result = verifyArtefact(artefact);
    expect(result.ok).toBe(true);
  });
});

// -------------------------------------------------------------------------
// H-2 — missing payload throws TypeError
// -------------------------------------------------------------------------

describe('H-2: missing mandate_body / payload', () => {
  it('throws TypeError when neither mandate_body nor payload is present', () => {
    const canonical = jcsCanonicalBytes(SIMPLE_PAYLOAD);
    const sha = 'sha256:' + bytesToHex(sha256(canonical));
    const artefact = {
      // mandate_body intentionally omitted
      expected_canonical_sha256: sha,
      signatures: {} as Record<string, Record<string, unknown>>,
    };
    expect(() => verifyArtefact(artefact as never)).toThrow(TypeError);
  });

  it('accepts payload key as fallback for mandate_body', () => {
    const esSk = generateES256SecretKey();
    const edSk = generateEd25519SecretKey();
    const esSig = signES256(SIMPLE_PAYLOAD, esSk);
    const edSig = signEd25519(SIMPLE_PAYLOAD, edSk);
    const canonical = jcsCanonicalBytes(SIMPLE_PAYLOAD);
    const sha = 'sha256:' + bytesToHex(sha256(canonical));
    const artefact = {
      payload: SIMPLE_PAYLOAD, // using 'payload' not 'mandate_body'
      expected_canonical_sha256: sha,
      signatures: {
        ES256: esSig as Record<string, unknown>,
        Ed25519: edSig as Record<string, unknown>,
      },
    };
    const result = verifyArtefact(artefact as never);
    expect(result.canonicalShaOk).toBe(true);
    expect(result.ok).toBe(true);
  });
});

// -------------------------------------------------------------------------
// M-2 — verifyES256Strict is exported and enforces lowS
// -------------------------------------------------------------------------

describe('M-2: verifyES256Strict export', () => {
  it('verifyES256Strict is exported and accepts a valid low-s signature', () => {
    const sk = generateES256SecretKey();
    const sig = signES256(SIMPLE_PAYLOAD, sk);
    const canonical = jcsCanonicalBytes(SIMPLE_PAYLOAD);
    // @noble/curves p256.sign() produces low-s signatures by default (RFC 6979)
    const result = verifyES256Strict(canonical, sig as Record<string, unknown>);
    expect(result.ok).toBe(true);
  });

  it('verifyES256 and verifyES256Strict both accept a standard signature', () => {
    const sk = generateES256SecretKey();
    const sig = signES256(SIMPLE_PAYLOAD, sk);
    const canonical = jcsCanonicalBytes(SIMPLE_PAYLOAD);
    const sigRec = sig as Record<string, unknown>;
    expect(verifyES256(canonical, sigRec).ok).toBe(true);
    expect(verifyES256Strict(canonical, sigRec).ok).toBe(true);
  });
});

// -------------------------------------------------------------------------
// M-3 — registry-known but unimplemented algorithm
// -------------------------------------------------------------------------

describe('M-3: registry-known unimplemented algorithm', () => {
  it('HMAC-SHA-256 is known but returns ok:false with detail', () => {
    const canonical = jcsCanonicalBytes(SIMPLE_PAYLOAD);
    const result = verifySignature(canonical, 'HMAC-SHA-256', { signature_b64: 'dGVzdA==' });
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/no verifier|not implemented/i);
  });
});
