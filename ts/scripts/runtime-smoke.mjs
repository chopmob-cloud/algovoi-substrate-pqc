/**
 * Cross-runtime smoke test for @algovoi/substrate-pqc.
 *
 * Verifies the full API surface works in Node, Bun, and Deno against the
 * existing AP2 PQ conformance fixtures. Outputs a deterministic pass/fail
 * summary suitable for the cross-runtime matrix document.
 *
 * Usage:
 *   node   scripts/runtime-smoke.mjs
 *   bun    scripts/runtime-smoke.mjs
 *   deno   --allow-read scripts/runtime-smoke.mjs
 */

import { readFileSync, existsSync } from 'node:fs';
import {
  jcsCanonicalSha256Hex,
  signES256,
  signEd25519,
  signFalcon1024,
  signMLDSA65,
  generateES256SecretKey,
  generateEd25519SecretKey,
  generateFalcon1024Keypair,
  generateMLDSA65Keypair,
  verifyArtefact,
  buildConvergenceArtefact,
  lookupSignatureAlgorithm,
  UnknownSignatureAlgorithmError,
  KNOWN_SIGNATURE_ALGORITHMS,
} from '../dist/index.js';

let pass = 0;
let fail = 0;
const fails = [];

function check(name, ok, detail = '') {
  if (ok) {
    pass++;
    console.log(`  PASS  ${name}`);
  } else {
    fail++;
    fails.push(`${name}${detail ? ': ' + detail : ''}`);
    console.log(`  FAIL  ${name}${detail ? ' — ' + detail : ''}`);
  }
}

console.log('\n=== algovoi-substrate-pqc cross-runtime smoke test ===\n');

// Runtime identification (best-effort across Node/Bun/Deno)
function identifyRuntime() {
  if (typeof Bun !== 'undefined') return `Bun ${Bun.version}`;
  if (typeof Deno !== 'undefined') return `Deno ${Deno.version.deno}`;
  if (typeof process !== 'undefined' && process.versions?.node) return `Node ${process.versions.node}`;
  return 'unknown runtime';
}
console.log(`Runtime: ${identifyRuntime()}\n`);

// --- 1. Registry ---
console.log('1. signature_algorithm registry:');
check('registry size = 12', KNOWN_SIGNATURE_ALGORITHMS.size === 12);
check(
  'lookup("Falcon-1024") returns NIST L5',
  lookupSignatureAlgorithm('Falcon-1024').notes.includes('Level 5'),
);
try {
  lookupSignatureAlgorithm('NotReal');
  check('unknown identifier throws', false, 'expected UnknownSignatureAlgorithmError');
} catch (e) {
  check('unknown identifier throws', e instanceof UnknownSignatureAlgorithmError);
}

// --- 2. Canonical bytes anchor ---
console.log('\n2. JCS canonical bytes anchor:');
const ap2Payload = {
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
const expected = 'sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0';
const got = jcsCanonicalSha256Hex(ap2Payload);
check('AP2 PaymentMandate canonical SHA matches published anchor', got === expected, `got ${got}`);

// --- 3. 4-scheme round-trip ---
console.log('\n3. 4-scheme round-trip + convergence artefact:');
const es = generateES256SecretKey();
const ed = generateEd25519SecretKey();
const fk = generateFalcon1024Keypair();
const mk = generateMLDSA65Keypair();

const signatures = {
  ES256: signES256(ap2Payload, es),
  Ed25519: signEd25519(ap2Payload, ed),
  'Falcon-1024': signFalcon1024(ap2Payload, fk.secretKey, fk.publicKey),
  'ML-DSA-65': signMLDSA65(ap2Payload, mk.secretKey, mk.publicKey),
};
const artefact = buildConvergenceArtefact(ap2Payload, signatures, {
  artefactId: 'cross-runtime-smoke-v0',
});
const v = verifyArtefact(artefact);
check('canonical SHA matches', v.canonicalShaOk);
check('all 4 signatures verify', v.signatures.length === 4 && v.signatures.every((s) => s.ok));

// --- 4. Cross-validation against ap2-pq-conformance fixtures ---
console.log('\n4. Cross-validation against ap2-pq-conformance:');
const fixtureCandidates = [
  'C:/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
  '/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
  '../../ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
];
const fixturePath = fixtureCandidates.find((p) => existsSync(p));
if (!fixturePath) {
  console.log('  SKIP  AP2 fixture not available locally (this is fine for CI)');
} else {
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf-8'));
  const fv = verifyArtefact(fixture);
  check(
    'AlgoVoi-side fixture canonical SHA matches',
    fv.canonicalShaOk,
    `expected ${fv.canonicalShaExpected}, got ${fv.canonicalShaRecomputed}`,
  );
  for (const s of fv.signatures) {
    check(`AlgoVoi-side ${s.algorithm} verifies`, s.ok, s.detail);
  }

  // PQSafe side: signs the same canonical bytes with ML-DSA-65
  const pqsafePath = fixturePath.replace(
    'algovoi-side/ap2-pqc-v0-algovoi-side.json',
    'pqsafe-side/ap2-pqc-v0-pqsafe-side.json',
  );
  if (existsSync(pqsafePath)) {
    const pqsafe = JSON.parse(readFileSync(pqsafePath, 'utf-8'));
    const rebound = {
      mandate_body: fixture.mandate_body,
      expected_canonical_sha256: pqsafe.expected_canonical_sha256,
      signatures: pqsafe.signatures,
    };
    const pv = verifyArtefact(rebound);
    check('PQSafe-side ML-DSA-65 verifies over identical canonical bytes', pv.ok);
  }
}

// --- Summary ---
console.log('\n=== Summary ===');
console.log(`Runtime: ${identifyRuntime()}`);
console.log(`Passed:  ${pass}`);
console.log(`Failed:  ${fail}`);
if (fail > 0) {
  console.log('\nFailures:');
  for (const f of fails) console.log(`  - ${f}`);
  if (typeof process !== 'undefined') process.exit(1);
  if (typeof Deno !== 'undefined') Deno.exit(1);
}
console.log('\nAll checks passed.\n');
