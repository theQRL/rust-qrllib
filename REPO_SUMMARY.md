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
- Dilithium: legacy pre-FIPS compatibility
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
- `cross-verify.yml`: reference implementation interoperability for Dilithium, ML-DSA-87, SPHINCS+, and XMSS
- `security.yml`: `cargo audit`, `cargo deny`, and dependency review
- Rust/npm direct dependencies are exact-pinned; GitHub Actions are SHA-pinned with version comments
- `pages.yml`: Vue/Tailwind demo build and GitHub Pages deployment
- `release.yml`: release-plz, checksums, SBOMs, attestations, and SLSA provenance

## Cross-Verification

Directionality:

- Dilithium, ML-DSA-87, and SPHINCS+ are bidirectional.
- XMSS is one-directional only: `rust-qrllib -> reference`.

XMSS one-directional verification is intentional because the RFC 8391 reference implementation has no deterministic seeded keypair API compatible with QRL's seed expansion.
