# Changelog

All notable changes to `algovoi-substrate-pqc` are documented here.
Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

---

## [0.1.2] — 2026-05-27 — Security patch

### Security

- **H-1 (HIGH)** — Closed vacuous-truth bypass: artefacts with zero declared
  signatures are now rejected by `ArtefactVerifyResult.ok` and
  `verify_artefact()` / `verifyArtefact()`. `all([])` / `[].every()` vacuously
  return `True`/`true`; the fix requires at least one positive verification
  signal before `ok` is `True`.
- **H-2 (HIGH)** — `verify_artefact()` (Python) now raises `ValueError` with a
  useful message when `mandate_body` or `payload` is absent, or when
  `expected_canonical_sha256` is absent. Previously raised a bare `KeyError`.

### Added

- `verifyES256Strict` (TypeScript) — ES256 verifier with `lowS: true` for
  callers needing malleability protection. `verifyES256` retains `lowS: false`
  for cross-implementation interop. Both exported from the package root.
- 7 Python security regression tests (`tests/test_security.py`).
- 7 TypeScript security regression tests (`ts/tests/security.test.ts`).
- Java `compactToDerEcdsa`: explicit runtime guard that SEQUENCE body length
  fits single-byte ASN.1 encoding (throws clearly for non-P-256 curves).

### Changed

- `verify_artefact()` (Python) now also accepts `payload` as a key fallback
  for `mandate_body`, matching the existing TypeScript convention.
- `pqcrypto` dependency pinned to `==0.4.0` (was `>=0.4.0,<0.5`).
- `.gitignore` documents that `_attestations/` is intentionally tracked.
- PHP `jsonEscape` ASCII-only scope documented in comment.
- Python `verify.py` module docstring notes absence of payload size limits.

### Fixed

- M-1: Documented that `cryptography >= 42` / OpenSSL 3.x uses RFC 6979
  deterministic ECDSA nonces by default; no API change required.

---

## [0.1.1] — 2026-05-26

- TypeScript package published to npm as `@algovoi/substrate-pqc@0.1.1`.
- Minor dependency and metadata alignment with 0.1.0 Python release.

---

## [0.1.0] — 2026-05-26 — Initial release

- `signature_algorithm` open-enum convention (12-row recommended-values
  registry) with case-sensitive fail-closed verifier discipline.
- JCS+PQC integration pattern: RFC 8785 canonical bytes → ES256 / Ed25519 /
  Falcon-1024 / ML-DSA-65 signature → artefact with
  `expected_canonical_sha256` byte-anchor.
- Cross-implementor byte-anchor convergence proof methodology.
- Python reference implementation (`algovoi-substrate-pqc` on PyPI).
- TypeScript reference implementation (`@algovoi/substrate-pqc` on npm).
- Multi-language verifier suite: Ruby, PHP, Perl, Java (Bouncy Castle).
- 24/24 cross-product matrix attestation (4 producers × 6 verifiers).
- Three audit-grade PQC implementations cross-validated: PQClean (Python),
  `@noble/post-quantum` (TypeScript), Bouncy Castle 1.84 (Java).
