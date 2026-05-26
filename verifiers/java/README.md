# Java verifier — Bouncy Castle PQC

Third audit-grade PQC implementation alongside PQClean (via `pqcrypto` on
Python) and `@noble/post-quantum` on TypeScript. Provides **independent
cross-implementor verification** of the AP2 PQ conformance fixtures and the
cross-product matrix artefacts produced by every other language.

## Upstream

| Primitive | Source | Status |
|---|---|---|
| ES256 (P-256 + SHA-256) | Bouncy Castle 1.84 `org.bouncycastle.jce.provider.BouncyCastleProvider` | Production |
| Ed25519 | Bouncy Castle 1.84 `org.bouncycastle.crypto.signers.Ed25519Signer` (lightweight API) | Production |
| ML-DSA-65 (FIPS 204 final) | Bouncy Castle 1.84 `org.bouncycastle.crypto.signers.MLDSASigner` + `MLDSAParameters.ml_dsa_65` | **Production** |
| Falcon-1024 (FIPS 206 / FN-DSA) | Bouncy Castle 1.84 `org.bouncycastle.pqc.crypto.falcon.FalconSigner` | **Experimental** classified by BC maintainers |

**Honest scope note on Falcon-1024:** Bouncy Castle classifies its
Falcon implementation as experimental as of 1.78+. Cross-impl verification
works (this directory demonstrates byte-for-byte agreement with PQClean
Falcon signatures), but the BC team recommends a hardening pass before
production use. ML-DSA-65 is production-grade in BC and is the recommended
PQC scheme for new deployments at NIST L3.

**Important class-selection note:** BC 1.84 ships BOTH
`pqc.crypto.crystals.dilithium.*` (the legacy CRYSTALS-Dilithium round-3
submission) AND `crypto.params.MLDSAParameters` + `crypto.signers.MLDSASigner`
(the FIPS 204 final ML-DSA). They are **not byte-compatible** with each
other. PQClean's `ml_dsa_65` and `@noble/post-quantum`'s `ml_dsa65` are
both FIPS 204 final — so the Java verifier uses `MLDSASigner`, not
`DilithiumSigner`. Using `DilithiumSigner` against FIPS 204 signatures
produces silent verification failures.

**Falcon-1024 public-key encoding bridge:** PQClean and `@noble/post-quantum`
emit Falcon-1024 public keys as 1793 bytes: `[1-byte logn header] [1792-byte
polynomial]`. BC's `FalconPublicKeyParameters` stores only the polynomial
(1792 bytes, no header). The verifier strips the leading 0x0a header byte
before passing to BC for substrate-symmetry.

## Quick start

```bash
cd verifiers/java
bash fetch-deps.sh                   # download BC + org.json jars (~10MB)
javac -cp "lib/*" -d out Verify.java
java -cp "out;lib/*" Verify          # Windows
java -cp "out:lib/*" Verify          # Linux/macOS
```

Optional explicit fixture argument:

```bash
java -cp "out;lib/*" Verify path/to/ap2-pqc-v0-algovoi-side.json
```

The verifier auto-discovers the AP2 PQ conformance fixture under
`C:/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json` if
no argument is passed. Replace with `/algo/...` on Linux/macOS.

## Scope statement

This verifier confirms, byte-for-byte, that artefacts signed by:

- Python `algovoi-substrate-pqc` (PQClean via `pqcrypto`)
- TypeScript `@algovoi/substrate-pqc` (Paul Miller `@noble/post-quantum`)
- Ruby producer (`verifiers/ruby/produce.rb`, OpenSSL stdlib)
- PHP producer (`verifiers/php/produce.php`, openssl + sodium)

…all verify under Bouncy Castle as an **independent third implementation**.

The substrate-author cross-implementor PQC convergence proof now spans
three audit-grade PQC implementations agreeing byte-for-byte against the
same canonical anchor.

## License

Apache 2.0, same as the rest of this repository. Bouncy Castle dependencies
are MIT-style licensed (BC license, MIT-compatible).
