# Multi-language verifiers

Cross-language verifier scripts demonstrating that the AlgoVoi-authored
substrate convention (JCS canonical bytes + `signature_algorithm`
open-enum + cross-implementor byte-anchor convergence proof) is
implementable in any language with standard cryptographic primitives.

Each verifier loads the AP2 PaymentMandate joint conformance fixture
from [`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance),
recomputes the JCS canonical bytes from `mandate_body`, confirms the
canonical SHA-256 matches the published byte-anchor
`sha256:cc8315f7…e0`, and verifies the available signatures against
the published public keys.

## Scope per language

| Language | ES256 | Ed25519 | Falcon-1024 | ML-DSA-65 | Audit-grade source |
|---|---|---|---|---|---|
| **Java** | ✓ via Bouncy Castle 1.84 | ✓ via Bouncy Castle `Ed25519Signer` | ✓ via BC `FalconSigner` *(experimental)* | ✓ via BC `MLDSASigner` *(production)* | **Third audit-grade PQC implementation** alongside PQClean + `@noble/post-quantum` |
| **Ruby** | ✓ via OpenSSL stdlib | ✓ via OpenSSL or `ed25519` gem | — | — | OpenSSL |
| **PHP** | ✓ via openssl extension | ✓ via sodium extension | — | — | OpenSSL + libsodium |
| **Perl** | ✓ via Crypt::OpenSSL::ECDSA | ✓ via Crypt::Ed25519 | — | — | OpenSSL |
| **Lua** | ✓ via lua-openssl | ✓ via lua-openssl | — | — | OpenSSL |
| **Elixir** | ✓ via :public_key | ✓ via :crypto | — | — | OpenSSL (Erlang/OTP) |

**PQC schemes (Falcon-1024, ML-DSA-65) are out of scope for the scripting
languages (Ruby / PHP / Perl / Lua / Elixir).** No audit-grade PQC libraries
exist for those ecosystems at this time. The PQC convergence proof is
established by **three** audit-grade implementations across the JVM and
non-JVM ecosystems:

1. **Python** `algovoi-substrate-pqc` → PQClean reference C via `pqcrypto`
2. **TypeScript** `@algovoi/substrate-pqc` → Paul Miller's `@noble/post-quantum`
3. **Java** Bouncy Castle 1.84 — `MLDSASigner` (production) +
   `FalconSigner` (experimental as classified by BC maintainers)

Three independent audit-grade PQC implementations agreeing byte-for-byte
against the same canonical anchor — see
[`../_attestations/2026-05-26-cross-product-matrix.md`](../_attestations/2026-05-26-cross-product-matrix.md)
for the full 4-producer × 6-verifier matrix.

### PQC cross-implementor contribution

The ML-DSA-65 fixture the audit-grade-PQC verifiers cross-validate against
was contributed by **PQSafe ([@rayc0](https://github.com/rayc0))** per the
AP2 #250 joint conformance fixture:
[`pqsafe-side/`](https://github.com/chopmob-cloud/ap2-pq-conformance/tree/main/pqsafe-side)
of [`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance).
PQSafe is named co-maintainer of the joint conformance repo per the
published policy. **Credit is scoped to that ML-DSA-65 contribution only.**
The substrate-author work (signature_algorithm convention, JCS+PQC
binding pattern, fail-closed verifier discipline, byte-anchor proof
methodology, multi-language verifier suite) is AlgoVoi's; PQSafe's
contribution is the independent ML-DSA-65 signature against the canonical
bytes the AlgoVoi-side specifies.

These scripting-language verifiers extend the substrate-author position
on the **canonicalisation + classical-signature** dimension. The full
language matrix is documented in [`../docs/CROSS_RUNTIME.md`](../docs/CROSS_RUNTIME.md).

## Why not vendor PQC primitives ourselves?

The alternative — vendoring PQClean's Falcon-1024 + ML-DSA-65 reference C
into this repo and binding via FFI for each scripting language — was
explicitly rejected during the package design phase (2026-05-26) for two
reasons:

1. **Falcon-1024 patent encumbrance.** Patent US7308097B2 covers parts of
   Falcon; the FRAND-style royalty-free pledge tied to NIST FIPS 206
   standardisation applies, but vendoring PQClean source makes this
   package a named redistributor of patent-encumbered code. The current
   design (depend on `pqcrypto` on Python and `@noble/post-quantum` on
   TypeScript) keeps the substrate-author layer a thin consumer of
   patent-encumbered primitives rather than a redistributor.

2. **FFI maintenance burden.** Each scripting-language FFI binding to
   PQClean's C ABI would require per-language audit + maintenance +
   patent disclosure surface. Not justified for the substrate-author
   position when the classical-scheme + canonical-bytes coverage already
   demonstrates the substrate is environment-independent.

## Per-verifier scope statement

Every verifier in this directory:

1. ✓ Loads the AP2 PQ conformance fixture JSON
2. ✓ Recomputes JCS canonical bytes from `mandate_body`
3. ✓ Confirms the recomputed SHA-256 matches `expected_canonical_sha256`
4. ✓ Verifies ES256 signature against the published public key
5. ✓ Verifies Ed25519 signature against the published public key
6. ✗ Does NOT verify Falcon-1024 (no audit-grade library in this language)
7. ✗ Does NOT verify ML-DSA-65 (no audit-grade library in this language)
8. ✓ Outputs deterministic pass/fail summary

## Invocation

From the repo root:

```bash
# Each verifier accepts an optional fixture path; defaults to a sibling
# C:/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json
# (or the platform-equivalent ../../ap2-pq-conformance/... path).

ruby   verifiers/ruby/verify.rb
php    verifiers/php/verify.php
perl   verifiers/perl/verify.pl
lua    verifiers/lua/verify.lua          # pending Lua install
elixir verifiers/elixir/verify.exs       # pending Elixir install
```

## License

Apache 2.0, same as the rest of this repository.
