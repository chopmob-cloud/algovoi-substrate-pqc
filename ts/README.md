# @algovoi/substrate-pqc

**TypeScript companion to `algovoi-substrate-pqc` on PyPI.**

AlgoVoi-authored substrate convention for binding canonical-JSON-serialised
payloads to post-quantum signature primitives, with a fail-closed verifier
discipline over an open-enum `signature_algorithm` registry.

```
npm install @algovoi/substrate-pqc
```

## What this package provides

| Component | Author | What it is |
|---|---|---|
| `signature_algorithm` open-enum registry | **AlgoVoi** | 12-row recommended-values table (case-sensitive lookup per RFC 7517 §4.1) |
| `UnknownSignatureAlgorithmError` fail-closed rule | **AlgoVoi** | Verifiers MUST reject unknown identifiers |
| JCS+PQC integration pattern | **AlgoVoi** | Canonical bytes via RFC 8785 → signature via chosen scheme |
| Cross-implementor byte-anchor convergence proof | **AlgoVoi** | One canonical payload, N schemes, byte-identical SHA-256 |

## Upstream primitives (NOT AlgoVoi-authored)

| Primitive | Implementation | Author / Source |
|---|---|---|
| Falcon-1024 (FIPS 206 / FN-DSA) | [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) v0.6.1+ | Paul Miller (MIT) |
| ML-DSA-65 (FIPS 204) | [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) v0.6.1+ | Paul Miller (MIT) |
| ES256 (P-256 + SHA-256) | [@noble/curves](https://github.com/paulmillr/noble-curves) v2+ | Paul Miller (MIT) |
| Ed25519 | [@noble/curves](https://github.com/paulmillr/noble-curves) v2+ | Paul Miller (MIT) |
| SHA-256 | [@noble/hashes](https://github.com/paulmillr/noble-hashes) v2+ | Paul Miller (MIT) |
| JCS canonicalisation (RFC 8785) | [canonicalize](https://www.npmjs.com/package/canonicalize) v3+ | Anders Rundgren / Erdtman et al. (Apache-2.0) |

The Falcon algorithm itself is the work of Fouque, Hoffstein, Kirchner,
Lyubashevsky, Pornin, Prest, Ricosset, Seiler, Whyte, and Zhang
(NIST PQC competition; standardised as NIST FIPS 206). The ML-DSA algorithm
(Dilithium / CRYSTALS-Dilithium) is the work of Bai, Ducas, Kiltz, Lepoint,
Lyubashevsky, Schwabe, Seiler, and Stehlé (standardised as NIST FIPS 204).

### Falcon-1024 patent disclosure

Patent **US7308097B2** may be applicable to parts of Falcon. William Whyte
(one of the Falcon designers and representative of OnBoard Security, the
current patent holder) has pledged, as part of the IP statements submitted to
NIST for the PQC project, that — with Falcon now selected for standardisation
(FIPS 206) — a worldwide non-exclusive license is granted for the purpose of
implementing the standard "without compensation and under reasonable terms
and conditions that are demonstrably free of any unfair discrimination". This
is a FRAND-style royalty-free pledge tied to FIPS 206 standardisation.

This package is a downstream consumer of `@noble/post-quantum` and is not a
redistributor of patent-encumbered Falcon source code. The Falcon-1024
primitive is provided through the `@noble/post-quantum` MIT-licensed
implementation. Any deployment using Falcon-1024 should review the FRAND
pledge for their use case.

## PQC cross-implementor contribution

The ML-DSA-65 cross-implementor fixture this TypeScript package verifies
against was contributed by **PQSafe ([@rayc0](https://github.com/rayc0))**
per [AP2 #250](https://github.com/google-agentic-commerce/AP2/issues/250)
and the joint conformance fixture at
[`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance).
The contribution scope is the
[`pqsafe-side/`](https://github.com/chopmob-cloud/ap2-pq-conformance/tree/main/pqsafe-side)
ML-DSA-65 signature over the canonical bytes the AlgoVoi-side fixture signs.
**Credit is scoped to that ML-DSA-65 contribution only; substrate-author
work for this package (signature_algorithm convention, JCS+PQC binding
pattern, fail-closed verifier discipline) is AlgoVoi's.**

## Cross-implementation interop

The 26-test suite includes byte-for-byte cross-validation against the
[`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance)
fixture set, which is the joint AlgoVoi (ES256 + Ed25519 + Falcon-1024) +
PQSafe (ML-DSA-65) deliverable for AP2 #250. Both fixtures use the identical
501-byte JCS canonical anchored at `sha256:cc8315f7…e0`.

| Implementation | Falcon-1024 | ML-DSA-65 | Verifies the same artefact? |
|---|---|---|---|
| Python `pqcrypto` (PQClean) | signer | signer | yes |
| TypeScript `@noble/post-quantum` | verifier | verifier | yes |

Two independent PQC implementations agreeing on the same canonical bytes is
the substrate-determinism property the AlgoVoi-substrate convention rests on.

## API surface (mirror of Python)

```typescript
import {
  // registry
  lookupSignatureAlgorithm,
  KNOWN_SIGNATURE_ALGORITHMS,
  UnknownSignatureAlgorithmError,

  // canonical bytes
  jcsCanonicalBytes,
  jcsCanonicalSha256Hex,

  // sign (sign, then verify; or build cross-impl artefacts)
  signES256,
  signEd25519,
  signFalcon1024,
  signMLDSA65,
  generateFalcon1024Keypair,
  generateMLDSA65Keypair,
  generateES256SecretKey,
  generateEd25519SecretKey,

  // verify
  verifyES256,
  verifyEd25519,
  verifyFalcon1024,
  verifyMLDSA65,
  verifySignature,
  verifyArtefact,

  // cross-implementor convergence
  buildConvergenceArtefact,
  canonicalAnchorFromPayload,
} from '@algovoi/substrate-pqc';
```

## Verifier discipline (fail-closed)

> Verifiers MUST treat unknown `signature_algorithm` values as opaque and
> refuse to verify.

This is the fail-closed normative rule. The TypeScript implementation
surfaces this as `UnknownSignatureAlgorithmError` thrown from
`lookupSignatureAlgorithm`. Implementors MAY declare any value; verifiers
MUST reject unknown values rather than guessing.

## ECDSA signature normalisation note

This package's `verifyES256` accepts both low-S and high-S ECDSA signatures
(passes `lowS: false` to `@noble/curves`). Many ECDSA implementations
(notably Python `cryptography`) emit signatures without restricting `s` to
the lower half of the curve order. The AlgoVoi-substrate verifier
prioritises cross-implementation interop: any valid ECDSA signature is
accepted. Deployments that need signature-malleability defence should
post-validate signatures with the strict `lowS: true` policy.

## Conformance to the canonicalisation discipline

This package is the AlgoVoi-authored TypeScript reference implementation of
the v2 (PQC-aware) canonicalisation discipline at
[`urn:x402:canonicalisation:jcs-rfc8785-v2`](https://docs.algovoi.co.uk/canonicalisation-substrate-v2),
the strictly-additive successor to
[`urn:x402:canonicalisation:jcs-rfc8785-v1`](https://docs.algovoi.co.uk/canonicalisation-substrate).
The canonicalisation core (RFC 8785 JCS plus schema-normalisation rules) is
unchanged between v1 and v2; v2 adds the `signature_algorithm` open-enum
registry and the fail-closed verifier discipline this package implements.

> **IETF Internet-Draft status.** An IETF Internet-Draft formalising
> `urn:x402:canonicalisation:jcs-rfc8785-v2` under the Independent Submissions
> stream is **pending** an active IETF list thread (May 2026) on the
> appropriate scope and use of the Independent Submissions stream for
> x402-related substrate documentation. The v2 discipline is published on
> `docs.algovoi.co.uk/canonicalisation-substrate-v2`, in this reference
> implementation, and in the
> [Substrate Adopters Registry](https://docs.algovoi.co.uk/adopters)
> independently of that process.

## Substrate adopters

AlgoVoi is recorded in the [Substrate Adopters Registry](https://docs.algovoi.co.uk/adopters)
as the substrate author (v1 and v2). Parties anchoring their own services
or specifications to `canon_version: jcs-rfc8785-v2` are recorded in the
registry via the [submission process](https://docs.algovoi.co.uk/adopters#how-to-submit-an-adoption-entry).
AlgoVoi validates submissions against the artefact's canonical bytes and
adds qualifying entries. v1 adopters retain their registry position; adopting
v2 adds a separate row pinned to `jcs-rfc8785-v2` rather than replacing the v1 row.

## License

Apache 2.0.

## Author

AlgoVoi (chopmob-cloud) — chopmob@gmail.com
