import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyArtefact } from '../src/verify.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function findFixture(relPath: string): string | undefined {
  const here = __dirname;
  // Walk up looking for a sibling ap2-pq-conformance directory.
  const candidates = [
    path.resolve(here, '..', '..', '..', 'ap2-pq-conformance', relPath),
    path.resolve(here, '..', '..', 'ap2-pq-conformance', relPath),
    path.resolve('C:/algo/ap2-pq-conformance', relPath),
    path.resolve('/algo/ap2-pq-conformance', relPath),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return undefined;
}

describe('Cross-validation against ap2-pq-conformance fixtures', () => {
  it('verifies the AlgoVoi-side fixture (ES256 + Ed25519 + Falcon-1024)', () => {
    const fixturePath = findFixture('algovoi-side/ap2-pqc-v0-algovoi-side.json');
    if (!fixturePath) {
      console.warn('skip: algovoi-side fixture not available');
      return;
    }
    const artefact = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
    const result = verifyArtefact(artefact);
    expect(
      result.canonicalShaOk,
      `expected ${result.canonicalShaExpected}, got ${result.canonicalShaRecomputed}`,
    ).toBe(true);
    expect(result.signatures.length).toBe(3);
    for (const s of result.signatures) {
      expect(s.ok, `${s.algorithm} failed: ${s.detail}`).toBe(true);
    }
  });

  it('verifies the PQSafe-side fixture (ML-DSA-65) against the AlgoVoi-side canonical bytes', () => {
    const algovoiPath = findFixture('algovoi-side/ap2-pqc-v0-algovoi-side.json');
    const pqsafePath = findFixture('pqsafe-side/ap2-pqc-v0-pqsafe-side.json');
    if (!algovoiPath || !pqsafePath) {
      console.warn('skip: ap2-pq-conformance fixtures not available');
      return;
    }
    const algovoiArt = JSON.parse(fs.readFileSync(algovoiPath, 'utf-8'));
    const pqsafeArt = JSON.parse(fs.readFileSync(pqsafePath, 'utf-8'));

    // The PQSafe-side fixture signs over the AlgoVoi-side canonical bytes
    // (cross-implementor convergence). Rebuild a verify-shaped artefact.
    const rebound = {
      mandate_body: algovoiArt.mandate_body,
      expected_canonical_sha256: pqsafeArt.expected_canonical_sha256,
      signatures: pqsafeArt.signatures,
    };
    const result = verifyArtefact(rebound);
    expect(result.canonicalShaOk).toBe(true);
    expect(result.signatures.length).toBe(1);
    expect(result.signatures[0]!.algorithm).toBe('ML-DSA-65');
    expect(result.signatures[0]!.ok, result.signatures[0]!.detail).toBe(true);
  });
});
