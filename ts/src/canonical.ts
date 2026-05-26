/**
 * Canonical-bytes derivation — RFC 8785 (Anders Rundgren) via `canonicalize`.
 *
 * Thin re-export of the Rundgren JCS canonicalisation rule for substrate-
 * author convenience. The canonicalisation algorithm itself is RFC 8785
 * (Anders Rundgren); the JS implementation is the `canonicalize` npm package
 * (Apache-2.0, by Erdtman et al.).
 *
 * AlgoVoi's substrate-author contribution is the binding of these canonical
 * bytes to a signature artefact (see `./sign` and `./proof`), not the
 * canonicalisation rule itself.
 */

import canonicalize from 'canonicalize';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

/** Return the RFC 8785 JCS canonical-byte representation of `payload`. */
export function jcsCanonicalBytes(payload: unknown): Uint8Array {
  const text = canonicalize(payload);
  if (text === undefined) {
    throw new TypeError('canonicalize() returned undefined; payload must be JSON-serialisable');
  }
  return new TextEncoder().encode(text);
}

/**
 * Return `"sha256:" + hex(sha256(jcs(payload)))` — the AlgoVoi-substrate
 * byte-anchor format used across conformance fixtures (e.g.
 * `sha256:cc8315f7…e0` for the AP2 PaymentMandate joint fixture).
 */
export function jcsCanonicalSha256Hex(payload: unknown): string {
  return 'sha256:' + bytesToHex(sha256(jcsCanonicalBytes(payload)));
}
