/**
 * Substrate-author signing helpers — wraps upstream primitives.
 *
 * Per-scheme signing helpers for ES256, Ed25519, Falcon-1024, ML-DSA-65.
 * Each helper:
 *
 * 1. Computes the RFC 8785 canonical-byte representation of the payload.
 * 2. Signs those canonical bytes under the chosen scheme.
 * 3. Returns an artefact dict in the AP2 PQC v0 schema shape.
 *
 * The cryptographic primitives are not AlgoVoi-authored. See README.md for
 * the upstream-attribution table.
 */

import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { falcon1024 } from '@noble/post-quantum/falcon.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { jcsCanonicalBytes } from './canonical.js';
import { lookupSignatureAlgorithm } from './registry.js';

function b64(bytes: Uint8Array): string {
  // Browser + Node compatible base64 encode.
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

export interface ES256SignatureArtefact {
  algorithm: 'ES256';
  curve: 'P-256';
  hash: 'SHA-256';
  publicKey_b64: string;
  signature_b64: string;
}

export interface Ed25519SignatureArtefact {
  algorithm: 'Ed25519';
  publicKey_b64: string;
  signature_b64: string;
}

export interface Falcon1024SignatureArtefact {
  algorithm: 'Falcon-1024';
  fips: 'FIPS 206 (FN-DSA)';
  nist_level: 5;
  publicKey_b64: string;
  signature_b64: string;
  signature_length_bytes: number;
  publicKey_length_bytes: number;
}

export interface MLDSA65SignatureArtefact {
  algorithm: 'ML-DSA-65';
  fips: 'FIPS 204';
  nist_level: 3;
  publicKey_b64: string;
  signature_b64: string;
  signature_length_bytes: number;
  publicKey_length_bytes: number;
}

/**
 * Sign `payload` (JCS-canonicalised) under ES256 (P-256 SHA-256).
 *
 * The signature is the compact `r || s` form (64 bytes), base64-encoded —
 * matching the AP2 PQC v0 `signature_compact_b64` shape. Note that the
 * Python sibling helper emits both DER-encoded and compact forms; this
 * TypeScript helper emits only the compact form for size + simplicity.
 *
 * @param payload — the payload to canonicalise + sign.
 * @param secretKey — raw 32-byte P-256 private scalar.
 * @returns ES256 signature artefact.
 */
export function signES256(payload: unknown, secretKey: Uint8Array): ES256SignatureArtefact {
  lookupSignatureAlgorithm('ES256');
  const canonical = jcsCanonicalBytes(payload);
  // p256.sign() defaults to prehash:true (i.e. internal sha256) + 'compact' format,
  // returning the 64-byte r||s signature directly.
  const sig = p256.sign(canonical, secretKey);
  const pub = p256.getPublicKey(secretKey, false); // uncompressed SEC1 (65 bytes)
  return {
    algorithm: 'ES256',
    curve: 'P-256',
    hash: 'SHA-256',
    publicKey_b64: b64(pub),
    signature_b64: b64(sig),
  };
}

/**
 * Sign `payload` (JCS-canonicalised) under Ed25519 (RFC 8032).
 *
 * @param payload — the payload to canonicalise + sign.
 * @param secretKey — raw 32-byte Ed25519 seed (the private key).
 * @returns Ed25519 signature artefact.
 */
export function signEd25519(payload: unknown, secretKey: Uint8Array): Ed25519SignatureArtefact {
  lookupSignatureAlgorithm('Ed25519');
  const canonical = jcsCanonicalBytes(payload);
  const sig = ed25519.sign(canonical, secretKey);
  const pub = ed25519.getPublicKey(secretKey);
  return {
    algorithm: 'Ed25519',
    publicKey_b64: b64(pub),
    signature_b64: b64(sig),
  };
}

/**
 * Sign `payload` (JCS-canonicalised) under Falcon-1024 (FIPS 206 / FN-DSA).
 *
 * Falcon-1024 primitive is by Paul Miller's `@noble/post-quantum` package
 * (MIT, audited). Patent encumbrance on Falcon-1024 (US7308097B2) has a
 * FRAND-style royalty-free pledge tied to FIPS 206 standardisation; see
 * README.md for the disclosure.
 *
 * @param payload — the payload to canonicalise + sign.
 * @param secretKey — Falcon-1024 secret key bytes (2305 bytes).
 * @param publicKey — Falcon-1024 public key bytes (1793 bytes).
 * @returns Falcon-1024 signature artefact.
 */
export function signFalcon1024(
  payload: unknown,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
): Falcon1024SignatureArtefact {
  lookupSignatureAlgorithm('Falcon-1024');
  const canonical = jcsCanonicalBytes(payload);
  const sig = falcon1024.sign(canonical, secretKey);
  return {
    algorithm: 'Falcon-1024',
    fips: 'FIPS 206 (FN-DSA)',
    nist_level: 5,
    publicKey_b64: b64(publicKey),
    signature_b64: b64(sig),
    signature_length_bytes: sig.length,
    publicKey_length_bytes: publicKey.length,
  };
}

/**
 * Sign `payload` (JCS-canonicalised) under ML-DSA-65 (FIPS 204).
 *
 * ML-DSA-65 primitive is by Paul Miller's `@noble/post-quantum` package
 * (MIT, audited). Public domain underlying primitive (CRYSTALS-Dilithium /
 * NIST FIPS 204).
 *
 * @param payload — the payload to canonicalise + sign.
 * @param secretKey — ML-DSA-65 secret key bytes (4032 bytes).
 * @param publicKey — ML-DSA-65 public key bytes (1952 bytes).
 * @returns ML-DSA-65 signature artefact.
 */
export function signMLDSA65(
  payload: unknown,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
): MLDSA65SignatureArtefact {
  lookupSignatureAlgorithm('ML-DSA-65');
  const canonical = jcsCanonicalBytes(payload);
  const sig = ml_dsa65.sign(canonical, secretKey);
  return {
    algorithm: 'ML-DSA-65',
    fips: 'FIPS 204',
    nist_level: 3,
    publicKey_b64: b64(publicKey),
    signature_b64: b64(sig),
    signature_length_bytes: sig.length,
    publicKey_length_bytes: publicKey.length,
  };
}

/** Generate a fresh Falcon-1024 keypair via @noble/post-quantum. */
export function generateFalcon1024Keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return falcon1024.keygen();
}

/** Generate a fresh ML-DSA-65 keypair via @noble/post-quantum. */
export function generateMLDSA65Keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return ml_dsa65.keygen();
}

/** Generate a fresh ES256 (P-256) secret-key scalar (32 bytes). */
export function generateES256SecretKey(): Uint8Array {
  return p256.utils.randomSecretKey();
}

/** Generate a fresh Ed25519 secret-key seed (32 bytes). */
export function generateEd25519SecretKey(): Uint8Array {
  return ed25519.utils.randomSecretKey();
}
