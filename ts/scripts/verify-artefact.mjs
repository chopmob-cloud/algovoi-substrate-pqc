/**
 * Standalone TS verifier CLI: takes an artefact path, prints pass/fail per scheme,
 * exits non-zero on failure. Used by the cross-product matrix harness.
 */
import { readFileSync } from 'node:fs';
import { verifyArtefact } from '../dist/index.js';

const path = process.argv[2];
if (!path) {
  console.error('usage: node verify-artefact.mjs <artefact.json>');
  process.exit(2);
}
const artefact = JSON.parse(readFileSync(path, 'utf-8'));
const r = verifyArtefact(artefact);
console.log(`canonical_sha_ok=${r.canonicalShaOk}`);
for (const s of r.signatures) {
  console.log(`${s.algorithm}: ${s.ok ? 'OK' : 'FAIL: ' + s.detail}`);
}
process.exit(r.ok ? 0 : 1);
