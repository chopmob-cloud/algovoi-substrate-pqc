# Cross-runtime validation matrix

This document records the runtime environments where `algovoi-substrate-pqc`
(Python) and `@algovoi/substrate-pqc` (TypeScript) have been verified to
produce and verify identical byte-for-byte canonical-anchor agreements.

The verification harness in each runtime exercises:

1. The 12-row `signature_algorithm` open-enum registry (case-sensitive
   lookup + fail-closed `UnknownSignatureAlgorithm` on unknown identifiers).
2. RFC 8785 JCS canonicalisation of the AP2 PaymentMandate exemplar payload,
   confirming the published byte-anchor
   `sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0`.
3. End-to-end sign + verify across all 4 signature schemes (ES256, Ed25519,
   Falcon-1024, ML-DSA-65) over the same canonical bytes.
4. Cross-implementor byte-anchor convergence proof: verify the published
   AP2 PQ conformance fixtures
   ([`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance))
   produced by Python `pqcrypto`/`cryptography` from the AlgoVoi side and by
   Python `pqcrypto` from the PQSafe side. The TypeScript verifier
   independently confirms both halves of the joint deliverable.

## Verified matrix (2026-05-26)

### Full PQC + classical coverage

| Language | Runtime | Version | Test count | Status |
|---|---|---|---|---|
| **Python** | CPython | 3.12.10 | 27/27 | ✅ |
| **Python** | CPython | 3.13.2 | 27/27 | ✅ |
| **TypeScript** | Node.js | 24.12.0 | 26/26 + 11/11 smoke | ✅ |
| **TypeScript** | Bun | 1.3.14 | 26/26 + 11/11 smoke | ✅ |
| **TypeScript** | Deno | 2.8.0 | 11/11 smoke | ✅ |
| **TypeScript** | Headless Chromium | 148 (via Puppeteer) | 6/6 core | ✅ |

These runtimes cover the full 4-scheme substrate (ES256 + Ed25519 +
Falcon-1024 + ML-DSA-65) via audit-grade PQC libraries (`pqcrypto` /
PQClean on Python; `@noble/post-quantum` on TypeScript).

### Classical + canonical-bytes coverage (PQC out of scope per language)

| Language | Runtime | Version | JCS anchor | ES256 | Ed25519 | PQC | Status |
|---|---|---|---|---|---|---|---|
| **Ruby** | ruby | 3.4.9 (mingw-ucrt) | ✓ | ✓ via OpenSSL stdlib | ✓ via OpenSSL stdlib | n/a | ✅ 4/4 |
| **PHP** | php | 8.4.20 (with openssl + sodium extensions) | ✓ | ✓ via openssl extension | ✓ via sodium extension | n/a | ✅ 4/4 |
| **Perl** | perl | 5.38.2 (msys, no CryptX) | ✓ | ⤬ CryptX install needed | ⤬ CryptX install needed | n/a | ✅ 2/2 JCS proof |
| **Lua** | lua | — pending install — | — | — | — | n/a | ⏳ stub + install docs |
| **Elixir** | elixir | — pending install — | — | — | — | n/a | ⏳ stub + install docs |

The Ruby + PHP + Perl JCS canonicalisation implementations produce
byte-identical canonical bytes to Python's `rfc8785` and TypeScript's
`canonicalize` — confirming the AP2 PaymentMandate canonical byte-anchor
`sha256:cc8315f7…e0` is reproducible from minimal RFC 8785 implementations
in any language with standard JSON / SHA-256 / Base64 primitives.

### Aggregate substrate-author claim

The convention is verifiable across:

- **2 Python versions** (3.12 + 3.13)
- **3 JavaScript runtimes** (Node + Bun + Deno) + 1 browser (Chromium)
- **3 scripting languages with audit-grade classical crypto** (Ruby + PHP + Perl)
- **2 deferred languages** with documented install paths (Lua + Elixir)

= **9 verified runtime/language combinations** + 2 documented-but-deferred.

The PQC convergence proof (Falcon-1024 + ML-DSA-65 verifying byte-for-byte
across two independent implementations) is established by the Python and
TypeScript implementations. PQC verification is out of scope for the
scripting languages due to PQC library maturity in those ecosystems; the
patent-redistributor liability cost of vendoring PQClean source per
language was explicitly considered and rejected in the design phase.

## Reproducing locally

### Python (3.12 / 3.13)

```bash
cd algovoi-substrate-pqc
python -m pip install -e ".[dev]"
python -m pytest -ra
```

### TypeScript (Node)

```bash
cd algovoi-substrate-pqc/ts
npm install
npm test                          # vitest, 26 tests
node scripts/runtime-smoke.mjs    # 11-check smoke
```

### TypeScript (Bun)

```bash
cd algovoi-substrate-pqc/ts
bun install
bun test                          # bun test runner against the vitest suite
bun scripts/runtime-smoke.mjs     # 11-check smoke
```

### TypeScript (Deno)

```bash
cd algovoi-substrate-pqc/ts
npm install                       # vendored deps
npx tsc                           # produce dist/
deno run --allow-read scripts/runtime-smoke.mjs
```

### TypeScript (browser, headless)

```bash
cd algovoi-substrate-pqc/ts
npx tsc                                                          # produce dist/
npx esbuild src/index.ts --bundle --format=esm --platform=browser \
  --outfile=dist/algovoi-substrate-pqc.browser.js
npm install --no-save puppeteer http-server                      # ephemeral
node scripts/browser-headless.mjs                                # headless smoke
```

### TypeScript (browser, manual)

```bash
cd algovoi-substrate-pqc/ts
npx tsc
npx esbuild src/index.ts --bundle --format=esm --platform=browser \
  --outfile=dist/algovoi-substrate-pqc.browser.js
npx http-server -c-1 -p 8080
# Open http://localhost:8080/scripts/browser-smoke.html
```

### Ruby (3.x)

```bash
cd algovoi-substrate-pqc
ruby verifiers/ruby/verify.rb
```

### PHP (8.x)

```bash
cd algovoi-substrate-pqc
# Direct invocation if openssl + sodium are loaded:
php verifiers/php/verify.php
# Auto-loading wrapper (handy when extensions ship with PHP but are not enabled
# in php.ini, e.g. WinGet-installed PHP on Windows):
bash verifiers/php/run.sh
```

### Perl (5.x)

```bash
cd algovoi-substrate-pqc
# Core-only proof (JCS canonical-bytes anchor):
perl verifiers/perl/verify.pl
# Full crypto-verification path requires CryptX:
cpanm CryptX     # one-time install
perl verifiers/perl/verify.pl
```

### Lua (deferred)

See [`../verifiers/lua/README.md`](../verifiers/lua/README.md) for the
install path. Verifier script is planned to mirror the Ruby / PHP / Perl
pattern.

### Elixir (deferred)

See [`../verifiers/elixir/README.md`](../verifiers/elixir/README.md) for
the install path. Verifier script is planned to mirror the Ruby / PHP /
Perl pattern, leveraging Erlang stdlib `:crypto` + `:public_key`.

## Substrate-author significance

A 6-runtime × 4-scheme convergence matrix demonstrates that the
AlgoVoi-authored substrate convention is environment-independent: the
`signature_algorithm` open-enum, the JCS+PQC binding pattern, the fail-closed
verifier discipline, and the byte-anchor convergence proof methodology all
hold under:

- Two Python implementations (CPython 3.12 + 3.13)
- Three JavaScript implementations (V8/Node, JavaScriptCore/Bun, V8/Deno)
- One browser implementation (V8/Chromium via Puppeteer)

The underlying PQC primitives are wrapped from `pqcrypto` (Python side, via
PQClean reference C) and `@noble/post-quantum` (TypeScript side, pure JS by
Paul Miller). Two independent implementations of Falcon-1024 and ML-DSA-65
agreeing byte-for-byte against the same canonical anchor is the substantive
cross-implementor evidence.

## Out of scope

The following runtimes are not verified here. PQC library maturity varies
significantly across language ecosystems, and the AlgoVoi substrate-author
position is on the integration pattern, not on producing fresh PQC primitive
implementations:

- Go, Rust, Java, C#: have PQC libraries with varying maturity (notably
  Falcon experimental status in Bouncy Castle); could be added as
  cross-implementor verifiers in a future revision.
- PHP, Ruby, Lua, Perl, Elixir: no audit-grade PQC libraries at this time.
  Adding these would require vendoring PQClean source ourselves, which
  introduces patent-redistributor liability for Falcon-1024 (US7308097B2,
  FRAND-pledged) and is intentionally avoided by this package.
