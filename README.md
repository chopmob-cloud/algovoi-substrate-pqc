# algovoi-substrate-pqc

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

## Position relative to the substrate-author work

This package sits **above** the audited PQC primitives and **alongside** the
[AlgoVoi canonicalisation discipline](https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/)
(`urn:x402:canonicalisation:jcs-rfc8785-v1`, AlgoVoi-authored IETF
Independent Submission, Informational).

| Layer | Owner | Artefact |
|---|---|---|
| L0 — Lattice mathematics, FIPS 204 / FIPS 206 standardisation | Academic cryptographers + NIST | — |
| L1 — PQC reference C implementations | PQClean | `PQClean/PQClean` repo |
| L2 — Python wrapper around PQClean | Backbone Authors | `pqcrypto` PyPI package |
| L3 — Classical primitives + JCS rule | Python Cryptographic Authority + Anders Rundgren | `cryptography`, `rfc8785` PyPI packages |
| **L4 — Canonicalisation discipline** | **AlgoVoi** | `urn:x402:canonicalisation:jcs-rfc8785-v1`, IETF I-D |
| **L4 — `signature_algorithm` open-enum + binding pattern** | **AlgoVoi** | This package |

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

## License

Apache 2.0.

This package is Apache-2.0 licensed, consistent with all upstream
dependencies (`pqcrypto`, `cryptography`, `rfc8785`).

## Contact

- Author: AlgoVoi (chopmob-cloud) — chopmob@gmail.com
- Source: https://github.com/chopmob-cloud/algovoi-substrate-pqc
- Cross-implementor reference fixture: https://github.com/chopmob-cloud/ap2-pq-conformance
- Canonicalisation discipline (IETF I-D): https://datatracker.ietf.org/doc/draft-hopley-x402-canonicalisation-jcs-v1/

## Co-maintainer policy

Contributors who land a substrate-aligned signature scheme (new family in the
registry, or a new cross-implementor convergence-proof against the same
canonical-bytes discipline) MAY be invited as co-maintainers of this
repository for the duration of their contribution. Attribution is
per-component; each contributor is named for the specific scheme or proof
they contribute.

This policy mirrors the `chopmob-cloud/ap2-pq-conformance` policy under which
PQSafe (rayc0) joined as co-maintainer with the ML-DSA-65 contribution.
