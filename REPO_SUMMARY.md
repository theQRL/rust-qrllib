# Repository Summary

## Overview

`rust-qrllib` is the Rust implementation of the Quantum Resistant Ledger cryptographic library.

Primary areas:

- `crates/qrllib`: core Rust cryptographic library
- `crates/qrllib-wasm`: wasm-bindgen wrappers for browser use
- `demo`: Vue + Tailwind browser demo for the compiled wasm package
- `.github/workflows`: Rust CI, ACVP, cross-verification, security, release, and GitHub Pages deployment

Supported algorithms:

- ML-DSA-87: primary FIPS 204 stateless signature scheme, ported in-repo from `go-qrllib`
- ML-KEM-1024: FIPS 203 key-encapsulation primitive (not a signature), ported in-repo from `go-qrllib`; standalone, not wallet-integrated
- SPHINCS+-256s robust: conservative hash-based stateless option
- XMSS: legacy QRL compatibility with strong statefulness caveats

## Test And Verification

The main checks are:

- `cargo fmt --all -- --check`
- `cargo test --workspace --locked`
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- `cargo llvm-cov --locked --package qrllib --summary-only`
- `cd demo && npm run build`

Additional workflow coverage:

- `acvp.yml`: ML-DSA-87 keygen/signing against NIST ACVP vectors
- `cross-verify.yml`: reference implementation interoperability for ML-DSA-87, SPHINCS+, and XMSS
- `security.yml`: `cargo audit`, `cargo deny`, and dependency review
- Rust/npm direct dependencies are exact-pinned; GitHub Actions are SHA-pinned with version comments
- `pages.yml`: Vue/Tailwind demo build and GitHub Pages deployment
- `release.yml`: release-plz, checksums, SBOMs, attestations, and SLSA provenance

## Cross-Verification

Directionality:

- ML-DSA-87, SPHINCS+, and XMSS are bidirectional.

The XMSS workflow proves both directions for `XMSS-SHA2_10_256` against
`xmss-reference` commit `7793c40`. That pin uses the pseudorandom private-key
derivation described as an example in RFC 8391 and closely aligned with QRL's
already-deployed construction. The `xmss::rfc8391` adapter supplies the direct
96-byte seed and RFC OID/public-key conventions needed to compare identical
keys despite QRL's 48-byte wallet-seed and three-byte descriptor conventions.
See `.github/cross-verify/README.md` and SECURITY.md "XMSS provenance and
standards alignment" for the scope and immutable-chain compatibility rationale.
