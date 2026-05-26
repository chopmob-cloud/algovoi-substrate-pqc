# AlgoVoi substrate-pqc — cross-product verification matrix (2026-05-26)

**Attestation ID:** `algovoi-substrate-pqc-cross-product-2026-05-26`
**Generated:** 2026-05-26T07:45:57Z
**Canonical payload:** stable AP2 PaymentMandate exemplar
**Byte-anchor consensus:** ✅ `sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0`

## Summary

Each producer signs the **identical** stable canonical payload under the
signature schemes its audit-grade libraries support. Each verifier then
runs against **every** producer's artefact. Cells report `<passing
checks>/<total checks>` per cell.

- **PQC schemes** (Falcon-1024, ML-DSA-65) are produced/verified only by
  Python (`pqcrypto`/PQClean) and TypeScript (`@noble/post-quantum`) —
  the two language ecosystems with audit-grade PQC libraries.
- **Classical schemes** (ES256, Ed25519) are produced by Python, TS,
  Ruby, PHP and verified by every available verifier.
- **Perl verifier** confirms the JCS canonical-bytes byte-anchor against
  every producer's artefact (using core modules); ES256/Ed25519
  verification in Perl requires `cpanm CryptX` (graceful SKIP if absent).

## Cross-product matrix

| Producer ↓ \ Verifier → | **python** | **ts** | **ruby** | **php** | **java** | **perl** |
|---|---|---|---|---|---|---|
| **python** | ✅ 5/5 | ✅ 5/5 | ✅ 4/4 | ✅ 4/4 | ✅ 6/6 | ✅ JCS 2/2 |
| **ts** | ✅ 5/5 | ✅ 5/5 | ✅ 4/4 | ✅ 4/4 | ✅ 6/6 | ✅ JCS 2/2 |
| **ruby** | ✅ 3/3 | ✅ 3/3 | ✅ 4/4 | ✅ 4/4 | ✅ 4/4 | ✅ JCS 2/2 |
| **php** | ✅ 3/3 | ✅ 3/3 | ✅ 4/4 | ✅ 4/4 | ✅ 4/4 | ✅ JCS 2/2 |

## Per-producer canonical SHA-256

| Producer | canonical_sha256 |
|---|---|
| python | `sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0` |
| ts | `sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0` |
| ruby | `sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0` |
| php | `sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0` |

**All 4 producers** agreed on the canonical byte-anchor.

## Cross-implementor partners

This convergence proof is a coalition deliverable. Acknowledgements:

- **PQSafe ([@rayc0](https://github.com/rayc0))** — cross-implementor
  partner on the ML-DSA-65 byte-anchor convergence per the AP2 #250
  joint conformance fixture. PQSafe's ML-DSA-65 signatures (produced
  with Python `pqcrypto`/PQClean) are verified by the TypeScript and
  Java sides of this matrix, providing one of the two independent
  ML-DSA-65 implementation paths in the cross-implementor proof.
  Joint conformance home: [`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance);
  PQSafe contributed the [`pqsafe-side/`](https://github.com/chopmob-cloud/ap2-pq-conformance/tree/main/pqsafe-side)
  half of the joint fixture and is named co-maintainer per the
  published policy.
- **Paul Miller ([@paulmillr](https://github.com/paulmillr))** —
  `@noble/post-quantum` author, providing the second audit-grade PQC
  implementation chain on the TypeScript side. Pure-JS Falcon-1024 +
  ML-DSA-65 in MIT-licensed code.
- **PQClean community** — reference C implementations of Falcon-1024
  and ML-DSA-65, exposed to Python via the
  [`pqcrypto`](https://pypi.org/project/pqcrypto/) package (Backbone
  Authors, Apache-2.0).
- **Bouncy Castle maintainers** — third audit-grade implementation
  via `MLDSASigner` (production) and `FalconSigner` (experimental),
  MIT-style licensed.
- **Anders Rundgren** — RFC 8785 JCS canonicalisation rule, the
  load-bearing canonicalisation discipline this entire proof rests
  on.

Without these upstream partners + cross-implementor contributors, the
matrix would not be reproducible. Substrate-author credit for the
convention + binding pattern + open-enum + fail-closed discipline is
AlgoVoi's; cross-implementor agreement is the coalition's.

## Substrate-author significance

- **Four independent JCS canonicalisations** (Python `rfc8785`,
  TypeScript `canonicalize`, Ruby minimal-JCS, PHP minimal-JCS) produce
  byte-identical canonical bytes from the same payload — confirming the
  AlgoVoi-authored substrate convention is reproducible from any
  language with standard JSON + SHA-256 primitives.
- **Cross-product verification** (every verifier against every producer
  artefact) demonstrates that signatures emitted in language X verify
  in language Y for the schemes available in each environment. The
  substrate convention is producer-verifier-symmetric.
- **Three audit-grade PQC implementation chains** — PQClean via
  `pqcrypto` on Python, pure-JS `@noble/post-quantum` on TypeScript,
  and Bouncy Castle on Java — produce or verify Falcon-1024 and
  ML-DSA-65 signatures over identical canonical bytes, with each
  implementation independently confirming the others'. PQSafe's
  ML-DSA-65 contribution (per AP2 #250) is the cross-implementor
  fixture this triangle agrees on.

## Reproduce locally

```bash
cd algovoi-substrate-pqc
python scripts/cross_product_matrix.py
```

The harness runs all 4 producers, all 5 verifiers, and regenerates this
attestation document. The exact canonical SHA-256 in the byte-anchor
consensus row should match across producers; if not, investigate
producer-side JCS implementation divergence.

## Scope statement (PQC out of scope per scripting language)

Falcon-1024 + ML-DSA-65 cannot be produced or verified in Ruby / PHP /
Perl / Lua / Elixir because no audit-grade PQC libraries exist in those
ecosystems at this time. Vendoring PQClean source per scripting
language was explicitly considered and rejected (2026-05-26) due to
Falcon-1024 patent (US7308097B2, FRAND-pledged) redistributor liability
+ per-language FFI maintenance burden. The AlgoVoi-substrate PQC
convergence proof is established by the Python + TypeScript
implementations.
