# Lua verifier (planned, pending runtime install)

This directory will host `verify.lua` once the Lua 5.4 + `luaossl` (or
`lua-openssl`) toolchain is provisioned on the build environment.

## Install path

Windows (via scoop):

```bash
scoop install lua          # Lua 5.4
scoop install luarocks
luarocks install luaossl   # binding to OpenSSL (ECDSA + Ed25519 via EVP)
luarocks install lua-cjson # JSON support
```

Linux / macOS (via system package manager + luarocks):

```bash
# Debian/Ubuntu
apt-get install lua5.4 lua-cjson luarocks
luarocks install luaossl

# macOS Homebrew
brew install lua luarocks
luarocks install luaossl
luarocks install lua-cjson
```

## Planned scope

`verify.lua` will mirror the Ruby / PHP / Perl verifiers:

1. Load the AP2 PQ conformance fixture JSON via `cjson`
2. Recompute JCS canonical bytes from `mandate_body` (minimal RFC 8785
   implementation: lexicographic key sort, integer decimals, minimum-escape
   strings)
3. Confirm canonical SHA-256 byte-anchor `sha256:cc8315f7…e0` via `openssl.digest`
4. Verify ES256 signature via `openssl.pkey` + `openssl.x509` parsing of the
   DER-encoded SubjectPublicKeyInfo + `EVP_DigestVerify` with SHA-256
5. Verify Ed25519 signature via `openssl.pkey` with `Ed25519` key-type
6. Document Falcon-1024 + ML-DSA-65 as out-of-scope (no Lua PQC library)
7. Output deterministic pass/fail summary

## Why deferred

The build environment that produced this repo at commit `38be40c` did not
have Lua installed. Adding Lua to the cross-runtime matrix requires a
~10-minute install step plus ~1 day of verifier-script work mirroring the
Ruby/PHP/Perl pattern. This is the right shape for a follow-up session
rather than a session-end push.

The substrate-author claim is **not** blocked by Lua being deferred —
Python (3.12 + 3.13), TypeScript (Node + Bun + Deno + headless Chromium),
Ruby (3.4), and PHP (8.4) already form a 7-runtime convergence proof on
the JCS+classical-signature dimension. Perl is added on the JCS-only
dimension (CryptX install pending for ES256+Ed25519).

## Reference

See [`../README.md`](../README.md) for the multi-language verifier scope
and the cross-implementor convergence proof methodology.
