# Elixir verifier (planned, pending runtime install)

This directory will host `verify.exs` once the Erlang/OTP + Elixir
toolchain is provisioned on the build environment.

## Install path

Windows (via scoop):

```bash
scoop install erlang        # Erlang/OTP 27+
scoop install elixir        # Elixir 1.17+
```

Linux / macOS (via official asdf or system package manager):

```bash
# asdf (recommended for version pinning)
asdf plugin add erlang
asdf plugin add elixir
asdf install erlang latest
asdf install elixir latest

# Debian/Ubuntu native
apt-get install erlang elixir

# macOS Homebrew
brew install erlang elixir
```

## Planned scope

`verify.exs` (run via `elixir verify.exs`) will mirror the Ruby / PHP /
Perl verifiers:

1. Load the AP2 PQ conformance fixture JSON via `:json` (OTP 27+) or
   `Jason` (community library)
2. Recompute JCS canonical bytes from `mandate_body` (minimal RFC 8785
   implementation: lexicographic key sort, integer decimals,
   minimum-escape strings, in idiomatic Elixir using pattern matching)
3. Confirm canonical SHA-256 byte-anchor `sha256:cc8315f7…e0` via
   `:crypto.hash(:sha256, canonical)`
4. Verify ES256 signature via `:public_key` (Erlang stdlib): decode the
   DER-encoded SubjectPublicKeyInfo, then
   `:public_key.verify(canonical, :sha256, signature_der, pubkey_record)`
5. Verify Ed25519 signature via `:crypto.verify(:eddsa, :sha512,
   canonical, signature, [pub_raw, :ed25519])` on OTP 22.1+
6. Document Falcon-1024 + ML-DSA-65 as out-of-scope (no audit-grade
   Elixir/Erlang PQC library)
7. Output deterministic pass/fail summary

## Notable Elixir-specific advantages

- **No external Crypto deps**. ES256 and Ed25519 are both available via
  Erlang stdlib (`:crypto` + `:public_key`), so the verifier runs on a
  bare Elixir + OTP install with no NIFs or third-party libraries. This
  is a stronger substrate-author claim than the Ruby/PHP/Perl verifiers
  (which need OpenSSL extensions or CryptX).

- **Pattern matching for JCS** is idiomatic — recursive sort + serialize
  fits Elixir's structure naturally.

## Why deferred

The build environment that produced this repo at commit `38be40c` did not
have Erlang/Elixir installed. Adding Elixir requires a ~10-minute install
plus ~1 day of verifier-script work. Right shape for a follow-up session.

## Reference

See [`../README.md`](../README.md) for the multi-language verifier scope
and the cross-implementor convergence proof methodology.
