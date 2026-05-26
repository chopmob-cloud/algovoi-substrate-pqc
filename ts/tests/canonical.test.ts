import { describe, expect, it } from 'vitest';
import { jcsCanonicalBytes, jcsCanonicalSha256Hex } from '../src/canonical.js';

describe('JCS canonicalisation (RFC 8785 via canonicalize)', () => {
  it('produces stable bytes under key reordering', () => {
    const a = jcsCanonicalBytes({ b: 1, a: 2 });
    const b = jcsCanonicalBytes({ a: 2, b: 1 });
    expect(a).toEqual(b);
  });

  it('sha256 hex is prefixed and 64 chars', () => {
    const d = jcsCanonicalSha256Hex({ a: 1 });
    expect(d.startsWith('sha256:')).toBe(true);
    expect(d.length).toBe('sha256:'.length + 64);
  });

  it('AP2 PaymentMandate exemplar matches the published byte-anchor', () => {
    // This is the same payload as the AlgoVoi-side fixture in
    // chopmob-cloud/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json
    // and the Python test_canonical.py exemplar.
    const payload = {
      amount: { currency: 'USD', minor_units: 4995 },
      constraints: [
        { type: 'merchant_id_allowlist', value: ['did:web:merchant.example.com'] },
        { type: 'expiry_unix_ms', value: 1782259200000 },
      ],
      issued_at: '2026-05-21T00:00:00Z',
      issued_at_ms: 1779667200000,
      issuer: 'did:web:wallet.example.org',
      merchant: 'did:web:merchant.example.com',
      nonce: '0x7b5ce8a4f1b9a4d2',
      schema: 'google-agentic-commerce/AP2 PaymentMandate',
      subject: 'did:web:agent.example.org#agent-7',
      vct: 'mandate.payment.1',
      version: '0.1',
    };
    expect(jcsCanonicalSha256Hex(payload)).toBe(
      'sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0',
    );
  });
});
