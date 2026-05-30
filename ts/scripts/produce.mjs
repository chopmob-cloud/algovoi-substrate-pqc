/**
 * TypeScript producer for the cross-product matrix.
 *
 * Generates a fresh AP2 PQC v0 artefact signed with all four schemes
 * (ES256 + Ed25519 + Falcon-1024 + ML-DSA-65) over the shared cross-product
 * canonical payload. Mirror of `scripts/produce.py`.
 *
 * Output:
 *   _attestations/2026-05-30-cross-product/producers/ts.json
 *
 * Usage:
 *   node scripts/produce.mjs              # default path
 *   node scripts/produce.mjs custom.json  # custom path
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildConvergenceArtefact,
  generateEd25519SecretKey,
  generateES256SecretKey,
  generateFalcon1024Keypair,
  generateMLDSA65Keypair,
  signEd25519,
  signES256,
  signFalcon1024,
  signMLDSA65,
  VERSION,
} from '../dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Same payload as the Python producer so canonical bytes are byte-identical
// across producers.
const PAYLOAD = {
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

const defaultOut = resolve(
  __dirname,
  '..',
  '..',
  '_attestations',
  '2026-05-30-cross-product',
  'producers',
  'ts.json',
);
const outPath = process.argv[2] ? resolve(process.argv[2]) : defaultOut;

const esSk = generateES256SecretKey();
const edSk = generateEd25519SecretKey();
const fk = generateFalcon1024Keypair();
const mk = generateMLDSA65Keypair();

const signatures = {
  ES256: signES256(PAYLOAD, esSk),
  Ed25519: signEd25519(PAYLOAD, edSk),
  'Falcon-1024': signFalcon1024(PAYLOAD, fk.secretKey, fk.publicKey),
  'ML-DSA-65': signMLDSA65(PAYLOAD, mk.secretKey, mk.publicKey),
};

const artefact = buildConvergenceArtefact(PAYLOAD, signatures, {
  artefactId: 'cross-product-v0-ts-side',
  anchoredTo: {
    thread: 'https://github.com/chopmob-cloud/algovoi-substrate-pqc',
    schema: 'AP2 PaymentMandate v0.1 (cross-product exemplar)',
    rfc: 'RFC 8785 (JCS)',
  },
  context: {
    producer: `typescript/@algovoi/substrate-pqc v${VERSION}`,
    producer_runtime:
      typeof Bun !== 'undefined'
        ? `bun/${Bun.version}`
        : typeof Deno !== 'undefined'
          ? `deno/${Deno.version.deno}`
          : `node/${process.versions.node}`,
    purpose:
      'TypeScript-side producer for the cross-product matrix; signs the ' +
      'stable canonical payload under all 4 schemes the package supports. ' +
      'Other producers (Python, Ruby, PHP) sign the IDENTICAL canonical ' +
      'payload and their artefacts are cross-verified by every available ' +
      'verifier.',
  },
});

await mkdir(dirname(outPath), { recursive: true });
await writeFile(outPath, JSON.stringify(artefact, null, 2) + '\n', 'utf-8');
console.log(`wrote ${outPath} (signatures: ${Object.keys(signatures).sort().join(', ')})`);
