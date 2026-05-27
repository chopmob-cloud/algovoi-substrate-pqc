/**
 * @algovoi/substrate-pqc — AlgoVoi substrate-author layer for JCS+PQC integration.
 *
 * TypeScript companion to the `algovoi-substrate-pqc` Python package on PyPI.
 *
 * AlgoVoi-authored substrate:
 *
 * - `signature_algorithm` open-enum convention (12-row recommended-values
 *   registry), with fail-closed verifier discipline.
 * - JCS+PQC integration pattern: canonical bytes via RFC 8785 (Anders
 *   Rundgren) → signature via chosen scheme → artefact with
 *   `expected_canonical_sha256` byte-anchor.
 * - Cross-implementor byte-anchor convergence proof methodology.
 *
 * Underlying primitives (we depend on, do not claim authorship):
 *
 * - Falcon-1024 / ML-DSA-65 — `@noble/post-quantum` (Paul Miller, MIT)
 * - ES256 — `@noble/curves` (Paul Miller, MIT)
 * - Ed25519 — `@noble/curves` (Paul Miller, MIT)
 * - SHA-256 — `@noble/hashes` (Paul Miller, MIT)
 * - JCS canonicalisation (RFC 8785) — `canonicalize` (Erdtman et al., Apache-2.0)
 * - AP2 PaymentMandate schema v0.1 — Google agentic-commerce (reference only)
 *
 * See README.md for the full upstream-attribution table including the
 * Falcon-1024 patent disclosure (US7308097B2 with FRAND pledge).
 */

export const VERSION = '0.1.2';

// registry
export {
  KNOWN_SIGNATURE_ALGORITHMS,
  SignatureAlgorithmFamily,
  type SignatureAlgorithmRecord,
  UnknownSignatureAlgorithmError,
  lookupSignatureAlgorithm,
} from './registry.js';

// canonical
export { jcsCanonicalBytes, jcsCanonicalSha256Hex } from './canonical.js';

// sign
export {
  signES256,
  signEd25519,
  signFalcon1024,
  signMLDSA65,
  generateFalcon1024Keypair,
  generateMLDSA65Keypair,
  generateES256SecretKey,
  generateEd25519SecretKey,
  type ES256SignatureArtefact,
  type Ed25519SignatureArtefact,
  type Falcon1024SignatureArtefact,
  type MLDSA65SignatureArtefact,
} from './sign.js';

// verify
export {
  verifyES256,
  verifyES256Strict,
  verifyEd25519,
  verifyFalcon1024,
  verifyMLDSA65,
  verifySignature,
  verifyArtefact,
  type VerifyResult,
  type ArtefactVerifyResult,
  type Artefact,
} from './verify.js';

// proof
export {
  canonicalAnchorFromPayload,
  buildConvergenceArtefact,
  type CanonicalAnchor,
  type BuildConvergenceArtefactOptions,
} from './proof.js';
