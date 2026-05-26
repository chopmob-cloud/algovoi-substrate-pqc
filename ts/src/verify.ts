/**
 * Substrate-author verification — wraps upstream primitives with fail-closed discipline.
 *
 * Per-scheme verifiers plus end-to-end artefact verification.
 *
 * The verifier discipline:
 *
 * 1. Recompute JCS canonical bytes from the artefact `mandate_body` (or
 *    explicit `canonical_bytes`).
 * 2. Confirm the recomputed canonical SHA-256 matches the artefact-declared
 *    `expected_canonical_sha256` byte-anchor.
 * 3. For each declared signature, look up the `signature_algorithm`
 *    identifier in the registry (case-sensitive). If unknown, throw
 *    `UnknownSignatureAlgorithmError` — the fail-closed substrate rule.
 * 4. Dispatch to the per-scheme verifier.
 */

import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { falcon1024 } from '@noble/post-quantum/falcon.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { jcsCanonicalBytes } from './canonical.js';
import { lookupSignatureAlgorithm } from './registry.js';

function b64d(s: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(s, 'base64'));
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/**
 * Extract the raw uncompressed P-256 public-key point (65 bytes, leading 0x04)
 * from a DER-encoded SubjectPublicKeyInfo blob.
 *
 * The DER structure is fixed for P-256: a SEQUENCE containing an AlgorithmIdentifier
 * SEQUENCE (id-ecPublicKey + prime256v1) and a BIT STRING containing the raw
 * uncompressed point. The point itself is the last 65 bytes, starting with the
 * 0x04 uncompressed-point marker.
 */
function extractP256RawFromDer(der: Uint8Array): Uint8Array {
  // Find the 0x04 uncompressed-point marker. For P-256 SubjectPublicKeyInfo,
  // this is always at byte 26 (after the BIT STRING header + unused-bits byte).
  // We do a tolerant search for the last occurrence of 0x04 followed by 64 bytes.
  for (let i = der.length - 65; i >= 0; i--) {
    if (der[i] === 0x04 && der.length - i >= 65) {
      return der.slice(i, i + 65);
    }
  }
  throw new Error('could not locate uncompressed P-256 point in DER SubjectPublicKeyInfo');
}

export interface VerifyResult {
  algorithm: string;
  ok: boolean;
  detail?: string;
}

export interface ArtefactVerifyResult {
  canonicalShaOk: boolean;
  canonicalShaRecomputed: string;
  canonicalShaExpected: string;
  signatures: VerifyResult[];
  ok: boolean;
}

function safeVerify(algorithm: string, fn: () => boolean): VerifyResult {
  try {
    const ok = fn();
    const result: VerifyResult = { algorithm, ok };
    if (!ok) {
      result.detail = 'signature did not verify';
    }
    return result;
  } catch (err) {
    const e = err as Error;
    return {
      algorithm,
      ok: false,
      detail: `${e.name}: ${e.message}`,
    };
  }
}

export function verifyES256(canonical: Uint8Array, sig: Record<string, unknown>): VerifyResult {
  return safeVerify('ES256', () => {
    // Public key: prefer raw `publicKey_b64`; fall back to extracting the raw
    // uncompressed point from DER-encoded `publicKeyDer` if present.
    let pub: Uint8Array;
    if (typeof sig['publicKey_b64'] === 'string') {
      pub = b64d(sig['publicKey_b64']);
    } else if (typeof sig['publicKeyDer'] === 'string') {
      pub = extractP256RawFromDer(b64d(sig['publicKeyDer']));
    } else {
      throw new TypeError('ES256 signature missing publicKey_b64 or publicKeyDer');
    }

    // Signature: prefer compact `signature_b64` / `signature_compact_b64`; fall
    // back to DER-encoded `signature_der` via the noble {format:'der'} option.
    //
    // We pass `lowS: false` for interop. Many ECDSA implementations (notably
    // Python `cryptography`) emit signatures without restricting `s` to the
    // lower half of the curve order. The `lowS: true` default in @noble/curves
    // would reject those even though they're cryptographically valid. The
    // AlgoVoi-substrate verifier prioritises cross-implementation interop, so
    // we accept any valid ECDSA signature. Implementations that need
    // malleability defence can post-validate signatures with `lowS: true`.
    const compactStr =
      (sig['signature_b64'] ?? sig['signature_compact_b64']) as string | undefined;
    const derStr = sig['signature_der'] as string | undefined;
    if (typeof compactStr === 'string') {
      return p256.verify(b64d(compactStr), canonical, pub, { lowS: false });
    }
    if (typeof derStr === 'string') {
      return p256.verify(b64d(derStr), canonical, pub, { format: 'der', lowS: false });
    }
    throw new TypeError(
      'ES256 signature missing signature_b64 / signature_compact_b64 / signature_der',
    );
  });
}

export function verifyEd25519(canonical: Uint8Array, sig: Record<string, unknown>): VerifyResult {
  return safeVerify('Ed25519', () => {
    const pub = b64d(sig['publicKey_b64'] as string);
    const sigBytes = b64d(sig['signature_b64'] as string);
    return ed25519.verify(sigBytes, canonical, pub);
  });
}

export function verifyFalcon1024(
  canonical: Uint8Array,
  sig: Record<string, unknown>,
): VerifyResult {
  return safeVerify('Falcon-1024', () => {
    const pub = b64d(sig['publicKey_b64'] as string);
    const sigBytes = b64d(sig['signature_b64'] as string);
    return falcon1024.verify(sigBytes, canonical, pub);
  });
}

export function verifyMLDSA65(canonical: Uint8Array, sig: Record<string, unknown>): VerifyResult {
  return safeVerify('ML-DSA-65', () => {
    const pub = b64d(sig['publicKey_b64'] as string);
    const sigBytes = b64d(sig['signature_b64'] as string);
    return ml_dsa65.verify(sigBytes, canonical, pub);
  });
}

const VERIFIERS: Record<string, (c: Uint8Array, s: Record<string, unknown>) => VerifyResult> = {
  ES256: verifyES256,
  Ed25519: verifyEd25519,
  'Falcon-1024': verifyFalcon1024,
  'ML-DSA-65': verifyMLDSA65,
};

/**
 * Dispatch verification for a single signature.
 *
 * Applies the fail-closed substrate rule: unknown `algorithm` throws
 * `UnknownSignatureAlgorithmError`.
 */
export function verifySignature(
  canonical: Uint8Array,
  algorithm: string,
  sig: Record<string, unknown>,
): VerifyResult {
  lookupSignatureAlgorithm(algorithm); // throws UnknownSignatureAlgorithmError
  const verifier = VERIFIERS[algorithm];
  if (!verifier) {
    return {
      algorithm,
      ok: false,
      detail: `algorithm "${algorithm}" is in the recommended-values registry but no verifier is implemented in this package`,
    };
  }
  return verifier(canonical, sig);
}

export interface Artefact {
  mandate_body?: unknown;
  payload?: unknown;
  expected_canonical_sha256: string;
  signatures: Record<string, Record<string, unknown>>;
}

/**
 * Verify an AP2 PQC v0 artefact end-to-end.
 *
 * If `mandate_body` is present, it is canonicalised to derive the bytes-anchor.
 * Otherwise `payload` is used. Either way the recomputed SHA-256 is compared
 * to `expected_canonical_sha256` before any per-signature verification.
 */
export function verifyArtefact(artefact: Artefact): ArtefactVerifyResult {
  const payload =
    artefact.mandate_body !== undefined ? artefact.mandate_body : artefact.payload;
  if (payload === undefined) {
    throw new TypeError('artefact must declare either `mandate_body` or `payload`');
  }
  const canonical = jcsCanonicalBytes(payload);
  const recomputed = 'sha256:' + bytesToHex(sha256(canonical));
  const expected = artefact.expected_canonical_sha256;
  const canonicalShaOk = recomputed === expected;

  const signatures: VerifyResult[] = [];
  for (const [algorithm, sig] of Object.entries(artefact.signatures ?? {})) {
    signatures.push(verifySignature(canonical, algorithm, sig));
  }

  return {
    canonicalShaOk,
    canonicalShaRecomputed: recomputed,
    canonicalShaExpected: expected,
    signatures,
    ok: canonicalShaOk && signatures.every((s) => s.ok),
  };
}
