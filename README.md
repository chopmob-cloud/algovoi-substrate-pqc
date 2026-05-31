> **AlgoVoi is available for acquisition** — [docs.algovoi.co.uk/acquisition](https://docs.algovoi.co.uk/acquisition)

---

# algovoi-substrate-pqc

[![PyPI](https://img.shields.io/pypi/v/algovoi-substrate-pqc?label=PyPI)](https://pypi.org/project/algovoi-substrate-pqc/)
[![npm](https://img.shields.io/npm/v/@algovoi/substrate-pqc?label=npm)](https://www.npmjs.com/package/@algovoi/substrate-pqc)
[![Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)](./LICENSE)
[![IETF I-D](https://img.shields.io/badge/companion%20IETF%20I--D-draft--hopley--x402--canonicalisation--jcs--v1-blue)](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/)

**AlgoVoi substrate-author layer for JCS+PQC integration.**

This package implements the AlgoVoi-authored substrate convention for binding
canonical-JSON-serialised payloads to post-quantum signature primitives, with
a fail-closed verifier discipline over an open-enum `signature_algorithm`
registry.

The underlying cryptographic primitives are **not** AlgoVoi-authored. This
package is a thin substrate-author layer over audited upstream libraries. See
the [upstream-attribution table](#upstream-primitives) below for the full
credit chain.

```
pip install algovoi-substrate-pqc
```

## What this package provides

| Component | Author | What it is |
|---|---|---|
| `signature_algorithm` open-enum registry | **AlgoVoi** | 12-row recommended-values table covering classical (ES256, ES256K, Ed25519, ECDSA) + PQC (Falcon-512/1024, ML-DSA-44/65/87, SLH-DSA-SHA2-128s) + HMAC (HMAC-SHA-256, HMAC-SHA-384) families. Case-sensitive lookup per RFC 7517 §4.1. |
| Fail-closed verifier discipline | **AlgoVoi** | Verifiers MUST treat unknown identifiers as opaque and refuse to verify. Implementors MAY declare any value. |
| JCS+PQC integration pattern | **AlgoVoi** | Canonical bytes via RFC 8785 → signature via chosen scheme → artefact with `expected_canonical_sha256` byte-anchor. |
| Cross-implementor byte-anchor convergence proof | **AlgoVoi** | One canonical payload, N signature schemes, byte-identical SHA-256 across implementations. |
| Standalone reference verifier glue | **AlgoVoi** | ~70 lines of Python orchestrating canonical-bytes recomputation + signature verification across all four schemes. |

## Upstream primitives

This package wraps existing audited primitives. Authorship of those primitives
belongs to the parties listed below, not to AlgoVoi:

| Primitive | Implementation | Author / Source |
|---|---|---|
| Falcon-1024 (FIPS 206 / FN-DSA) | [PQClean](https://github.com/PQClean/PQClean) reference C, exposed via [`pqcrypto`](https://pypi.org/project/pqcrypto/) v0.4.0+ | PQClean community + Backbone Authors (Apache-2.0) |
| ML-DSA-65 (FIPS 204) | [PQClean](https://github.com/PQClean/PQClean) reference C, exposed via [`pqcrypto`](https://pypi.org/project/pqcrypto/) v0.4.0+ | PQClean community + Backbone Authors (Apache-2.0) |
| ES256 / Ed25519 / SHA-256 | [`cryptography`](https://pypi.org/project/cryptography/) v42+ + stdlib `hashlib` | Python Cryptographic Authority + NIST FIPS 180-4 |
| JCS canonicalisation (RFC 8785) | [`rfc8785`](https://pypi.org/project/rfc8785/) v0.1.4 | Anders Rundgren et al. |
| AP2 PaymentMandate schema v0.1 | Schema reference only (no code dependency) | Google agentic-commerce |

The Falcon algorithm itself is the work of Fouque, Hoffstein, Kirchner,
Lyubashevsky, Pornin, Prest, Ricosset, Seiler, Whyte, and Zhang
(NIST PQC competition; standardised as NIST FIPS 206). The ML-DSA algorithm
(Dilithium / CRYSTALS-Dilithium) is the work of Bai, Ducas, Kiltz, Lepoint,
Lyubashevsky, Schwabe, Seiler, and Stehlé (standardised as NIST FIPS 204).

## PQC cross-implementor contribution

The ML-DSA-65 cross-implementor fixture this package verifies against was
contributed by **PQSafe ([@rayc0](https://github.com/rayc0))** per the
[AP2 #250 joint conformance fixture](https://github.com/chopmob-cloud/ap2-pq-conformance).
The contribution scope is the
[`pqsafe-side/`](https://github.com/chopmob-cloud/ap2-pq-conformance/tree/main/pqsafe-side)
ML-DSA-65 signature over the same canonical bytes the AlgoVoi-side fixture
signs (FIPS 204 / NIST Level 3). PQSafe is named co-maintainer of
`chopmob-cloud/ap2-pq-conformance` (the joint conformance repo) per the
published policy. **Credit is scoped to that ML-DSA-65 contribution only;
substrate-author work for this package (signature_algorithm convention,
JCS+PQC binding pattern, fail-closed verifier discipline, byte-anchor
proof methodology) is AlgoVoi's.**

## Position relative to the substrate-author work

This package sits **above** the audited PQC primitives and **alongside** the
AlgoVoi-authored canonicalisation discipline. It emits receipts under
[`urn:x402:canonicalisation:jcs-rfc8785-v2`](https://docs.algovoi.co.uk/canonicalisation-substrate-v2)
(PQC-aware), the strictly-additive successor to
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

| Layer | Owner | Artefact |
|---|---|---|
| L0 — Lattice mathematics, FIPS 204 / FIPS 206 standardisation | Academic cryptographers + NIST | — |
| L1 — PQC reference C implementations | PQClean | `PQClean/PQClean` repo |
| L2 — Python wrapper around PQClean | Backbone Authors | `pqcrypto` PyPI package |
| L3 — Classical primitives + JCS rule | Python Cryptographic Authority + Anders Rundgren | `cryptography`, `rfc8785` PyPI packages |
| **L4 — Canonicalisation discipline v1** | **AlgoVoi** | `urn:x402:canonicalisation:jcs-rfc8785-v1`, AlgoVoi-authored, IETF Independent Submission Informational |
| **L4 — Canonicalisation discipline v2 (PQC-aware)** | **AlgoVoi** | `urn:x402:canonicalisation:jcs-rfc8785-v2`, AlgoVoi-authored, IETF I-D filing pending the active IETF list thread on Independent Submissions stream scope |
| **L4 — `signature_algorithm` open-enum + binding pattern** | **AlgoVoi** | This package (codifies v2 normatively) |

AlgoVoi's substrate-author contribution is **the convention, the binding, and
the proof methodology**, not the primitives.

## Cross-implementor byte-anchor convergence

The AlgoVoi substrate-author position rests on byte-anchor convergence:
multiple independent signature schemes verifying against the **identical**
canonical-byte representation of a single payload. The reference exemplar is
the AP2 PaymentMandate joint conformance fixture at
[`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance):

| Side | Schemes | Canonical SHA-256 |
|---|---|---|
| `algovoi-side/` | ES256 + Ed25519 + Falcon-1024 | `sha256:cc8315f7…e0` |
| `pqsafe-side/` (PQSafe co-contributor) | ML-DSA-65 | `sha256:cc8315f7…e0` |

Four signature schemes, one canonical payload, byte-identical SHA-256 across
implementations. This package is the reference implementation of that
convergence-proof methodology.

## Verifier rule (fail-closed)

> Verifiers MUST treat unknown `signature_algorithm` values as opaque and
> refuse to verify.

This rule is the fail-closed normative discipline that allows the
`signature_algorithm` registry to evolve without breaking schema changes.
Implementors MAY declare any value. Verifiers MUST reject unknown values or
escalate to a registered extension, rather than guessing.

The Python implementation surfaces this rule as
`UnknownSignatureAlgorithm` raised from `lookup_signature_algorithm()`.

## Tests

```bash
# Python (34 tests)
pip install -e .[dev]
python -m pytest tests/ -v

# TypeScript (33 tests)
cd ts && npm install && npm test
```

## License

Apache 2.0.

This package is Apache-2.0 licensed, consistent with all upstream
dependencies (`pqcrypto`, `cryptography`, `rfc8785`).

## Contact

- Author: AlgoVoi (chopmob-cloud) — chopmob@gmail.com
- Source: https://github.com/chopmob-cloud/algovoi-substrate-pqc
- Cross-implementor reference fixture: https://github.com/chopmob-cloud/ap2-pq-conformance
- Canonicalisation discipline v1: https://docs.algovoi.co.uk/canonicalisation-substrate (also at IETF datatracker as draft-hopley-x402-canonicalisation-jcs-v1)
- Canonicalisation discipline v2 (PQC-aware): https://docs.algovoi.co.uk/canonicalisation-substrate-v2 (IETF I-D filing pending IETF list thread on Independent Submissions stream scope)

## Adopters

Parties pinning `canon_version: jcs-rfc8785-v2` in publicly-citable artefacts
are recorded in the [Substrate Adopters Registry](https://docs.algovoi.co.uk/adopters)
alongside v1 adopters. Current v2 adopters:

- **AlgoVoi** -- this reference implementation (Python + npm packages
  published 2026-05-26). Cross-validated byte-for-byte across four
  audit-grade PQC implementations (PQClean via `pqcrypto`,
  `@noble/post-quantum`, Bouncy Castle 1.84, RustCrypto `ml-dsa` +
  `pqcrypto-falcon`). 48/48 cells PASS across 6 producers × 8 verifiers.

To request listing as a v2 adopter, follow the
[submission process](https://docs.algovoi.co.uk/adopters#how-to-submit-an-adoption-entry).
AlgoVoi validates submissions against the artefact's canonical bytes and
adds qualifying entries.

v1 adopters retain their registry position. Adopting v2 adds a separate
row pinned to `jcs-rfc8785-v2` rather than replacing the v1 row.

## Acknowledgments

The v2 discipline is solely AlgoVoi-authored. AlgoVoi acknowledges with
thanks the post-quantum contribution and reference-implementation work that
makes the cross-implementor convergence proof empirically possible:

**Post-quantum contribution (v2-specific):**

- **PQSafe** ([@rayc0](https://github.com/rayc0)) -- ML-DSA-65 (FIPS 204)
  signature contribution over the AP2 PaymentMandate canonical bytes
  ([chopmob-cloud/ap2-pq-conformance#1](https://github.com/chopmob-cloud/ap2-pq-conformance/pull/1),
  merged 2026-05-26). **Credit is scoped to this ML-DSA-65 contribution only.**

**Audit-grade PQC implementations cross-validated in the matrix:**

- [PQClean](https://github.com/PQClean/PQClean) (via [`pqcrypto`](https://pypi.org/project/pqcrypto/)) -- PQClean community + Backbone Authors
- [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) -- Paul Miller
- [Bouncy Castle](https://www.bouncycastle.org/) 1.84 (`MLDSASigner` for FIPS 204 final; experimental `FalconSigner`) -- Bouncy Castle community
- [`pqcrypto-falcon`](https://crates.io/crates/pqcrypto-falcon) + [`ml-dsa`](https://crates.io/crates/ml-dsa) (Rust) -- PQClean C wrapper (Falcon) + RustCrypto FIPS 204

The four audit-grade PQC implementations agree byte-for-byte across the
48-cell (6-producer × 8-verifier) matrix. The substrate-author position rests
on this independent multi-author cross-validation, not on AlgoVoi self-claim.

**Classical primitives and JCS library wrapped:**

- [`cryptography`](https://pypi.org/project/cryptography/) (Python) -- Python Cryptographic Authority
- [`rfc8785`](https://pypi.org/project/rfc8785/) (Python) -- Anders Rundgren et al. (RFC 8785 reference implementation)
- [`@noble/curves`](https://github.com/paulmillr/noble-curves) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (TypeScript) -- Paul Miller
- [`canonicalize`](https://www.npmjs.com/package/canonicalize) (TypeScript) -- Samuel Erdtman

**v1 validator and contributor acknowledgments** (the broader cross-impl
validation matrix v2 builds on) are recorded at
[docs.algovoi.co.uk/canonicalisation-substrate#acknowledgments-and-external-contributions](https://docs.algovoi.co.uk/canonicalisation-substrate#acknowledgments-and-external-contributions)
and in the [`chopmob-cloud/algovoi-substrate`](https://github.com/chopmob-cloud/algovoi-substrate) README.

## Co-maintainer policy

Contributors who land a substrate-aligned signature scheme (new family in the
registry, or a new cross-implementor convergence-proof against the same
canonical-bytes discipline) MAY be invited as co-maintainers of this
repository for the duration of their contribution. Attribution is
per-component; each contributor is named for the specific scheme or proof
they contribute.

This policy mirrors the `chopmob-cloud/ap2-pq-conformance` policy under which
PQSafe (rayc0) joined as co-maintainer with the ML-DSA-65 contribution.
