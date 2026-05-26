/**
 * Cross-implementor byte-anchor convergence proof — AlgoVoi-authored methodology.
 *
 * One canonical payload, N independent signature schemes, byte-identical
 * SHA-256 across implementations. TypeScript twin of the Python `proof`
 * module.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import { jcsCanonicalBytes } from './canonical.js';

function b64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]!);
  }
  return btoa(bin);
}

export interface CanonicalAnchor {
  bytes: Uint8Array;
  sha256HexPrefixed: string;
  length: number;
  b64: string;
  hex: string;
}

/** Compute the canonical-bytes anchor for `payload`. */
export function canonicalAnchorFromPayload(payload: unknown): CanonicalAnchor {
  const bytes = jcsCanonicalBytes(payload);
  return {
    bytes,
    sha256HexPrefixed: 'sha256:' + bytesToHex(sha256(bytes)),
    length: bytes.length,
    b64: b64(bytes),
    hex: bytesToHex(bytes),
  };
}

export interface BuildConvergenceArtefactOptions {
  artefactId: string;
  canonicalizer?: string;
  anchoredTo?: Record<string, unknown>;
  context?: Record<string, unknown>;
}

/**
 * Construct a cross-implementor byte-anchor convergence artefact in the
 * AP2 PQC v0 schema shape.
 */
export function buildConvergenceArtefact(
  payload: unknown,
  signatures: Record<string, Record<string, unknown>>,
  options: BuildConvergenceArtefactOptions,
): Record<string, unknown> {
  const anchor = canonicalAnchorFromPayload(payload);
  return {
    schema_version: '1.0',
    artefact_id: options.artefactId,
    canonicalizer: options.canonicalizer ?? 'canonicalize@3.0.0',
    published_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    anchored_to: options.anchoredTo ?? {},
    context: options.context ?? {},
    mandate_body: payload,
    expected_jcs_bytes_b64: anchor.b64,
    expected_jcs_bytes_hex: anchor.hex,
    expected_jcs_bytes_length: anchor.length,
    expected_canonical_sha256: anchor.sha256HexPrefixed,
    signatures,
  };
}
