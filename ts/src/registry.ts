/**
 * `signature_algorithm` open-enum registry — AlgoVoi-authored convention.
 *
 * TypeScript port of the Python `algovoi_substrate_pqc.registry` module.
 * The convention is AlgoVoi-authored; the signature primitives are not.
 * See README.md for the upstream-attribution table.
 *
 * Per the convention: implementors MAY emit any value. Verifiers MUST treat
 * unknown identifiers as opaque and refuse to verify (fail-closed).
 * Lookups are case-sensitive per RFC 7517 §4.1.
 */

export const SignatureAlgorithmFamily = {
  CLASSICAL: 'Classical',
  PQC: 'PQC',
  PQC_STATELESS_HASH: 'PQC stateless-hash',
  HMAC: 'HMAC',
} as const;

export type SignatureAlgorithmFamily =
  (typeof SignatureAlgorithmFamily)[keyof typeof SignatureAlgorithmFamily];

export interface SignatureAlgorithmRecord {
  readonly identifier: string;
  readonly family: SignatureAlgorithmFamily;
  readonly source: string;
  readonly notes: string;
}

const _records: SignatureAlgorithmRecord[] = [
  {
    identifier: 'ECDSA',
    family: SignatureAlgorithmFamily.CLASSICAL,
    source: 'Generic ECDSA',
    notes:
      'Backward-compat alias for AP2 v0.1 emitters. Curve- and hash-ambiguous. ' +
      'New deployments SHOULD use the specific JOSE identifier (ES256 / ES256K / ES384 / ES512) ' +
      'corresponding to the curve and hash actually in use.',
  },
  {
    identifier: 'ES256',
    family: SignatureAlgorithmFamily.CLASSICAL,
    source: 'RFC 7518 §3.4',
    notes: 'ECDSA P-256 SHA-256.',
  },
  {
    identifier: 'ES256K',
    family: SignatureAlgorithmFamily.CLASSICAL,
    source: 'RFC 8812',
    notes: 'ECDSA secp256k1 SHA-256.',
  },
  {
    identifier: 'Ed25519',
    family: SignatureAlgorithmFamily.CLASSICAL,
    source: 'RFC 8032 / RFC 8037',
    notes: 'EdDSA Ed25519.',
  },
  {
    identifier: 'ML-DSA-44',
    family: SignatureAlgorithmFamily.PQC,
    source: 'FIPS 204 / draft-ietf-cose-dilithium',
    notes: 'NIST Level 2.',
  },
  {
    identifier: 'ML-DSA-65',
    family: SignatureAlgorithmFamily.PQC,
    source: 'FIPS 204 / draft-ietf-cose-dilithium',
    notes: 'NIST Level 3.',
  },
  {
    identifier: 'ML-DSA-87',
    family: SignatureAlgorithmFamily.PQC,
    source: 'FIPS 204 / draft-ietf-cose-dilithium',
    notes: 'NIST Level 5.',
  },
  {
    identifier: 'Falcon-512',
    family: SignatureAlgorithmFamily.PQC,
    source: 'FIPS 206 (FN-DSA)',
    notes: 'NIST Level 1.',
  },
  {
    identifier: 'Falcon-1024',
    family: SignatureAlgorithmFamily.PQC,
    source: 'FIPS 206 (FN-DSA)',
    notes: 'NIST Level 5.',
  },
  {
    identifier: 'SLH-DSA-SHA2-128s',
    family: SignatureAlgorithmFamily.PQC_STATELESS_HASH,
    source: 'FIPS 205',
    notes: 'SPHINCS+ small.',
  },
  {
    identifier: 'HMAC-SHA-256',
    family: SignatureAlgorithmFamily.HMAC,
    source: 'RFC 2104',
    notes: 'Internal-channel only.',
  },
  {
    identifier: 'HMAC-SHA-384',
    family: SignatureAlgorithmFamily.HMAC,
    source: 'RFC 2104 / FIPS 198-1',
    notes: 'PQC-conservative HMAC.',
  },
];

export const KNOWN_SIGNATURE_ALGORITHMS: ReadonlyMap<string, SignatureAlgorithmRecord> =
  new Map(_records.map((r) => [r.identifier, r] as const));

/**
 * Raised by `lookupSignatureAlgorithm` when an identifier is not in the
 * recommended-values registry.
 *
 * Per the AlgoVoi-substrate convention, verifiers MUST treat unknown
 * `signature_algorithm` values as opaque and refuse to verify. This error
 * is the canonical signal of that condition.
 */
export class UnknownSignatureAlgorithmError extends Error {
  readonly identifier: string;
  constructor(identifier: string) {
    super(
      `unknown signature_algorithm identifier ${JSON.stringify(identifier)}; ` +
        `per the AlgoVoi-substrate convention verifiers MUST treat unknown ` +
        `values as opaque and refuse to verify`,
    );
    this.name = 'UnknownSignatureAlgorithmError';
    this.identifier = identifier;
  }
}

/**
 * Look up a `signature_algorithm` identifier (case-sensitive per RFC 7517 §4.1).
 *
 * Throws `UnknownSignatureAlgorithmError` if the identifier is not registered.
 * This is the fail-closed substrate rule.
 */
export function lookupSignatureAlgorithm(identifier: string): SignatureAlgorithmRecord {
  const rec = KNOWN_SIGNATURE_ALGORITHMS.get(identifier);
  if (!rec) {
    throw new UnknownSignatureAlgorithmError(identifier);
  }
  return rec;
}
