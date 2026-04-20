# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in `rust-qrllib`, please report it responsibly:

1. Do not open a public issue.
2. Email security concerns to [security@theqrl.org](mailto:security@theqrl.org).
3. Or report via [https://www.theqrl.org/security-report/](https://www.theqrl.org/security-report/).
4. Include detailed steps to reproduce.
5. Allow reasonable time for a fix before public disclosure.

## Threat Model

This library assumes a trusted execution environment, a secure operating-system random source, no physical memory-probing attacks, and correct caller behavior. XMSS callers must manage state correctly.

This library protects against post-quantum signature forgery under the assumptions of the configured algorithm. It does not protect against compromised hosts, weak system randomness, application-level replay/rate-limit failures, or XMSS index reuse.

### Signing modes (ML-DSA-87 and Dilithium)

Both ML-DSA-87 and the legacy Dilithium signer expose two signing modes per FIPS 204 §3.7:

- **Deterministic (default).** `sign` / `seal` produce the same signature every time for a given (secret key, message) pair. This is the mode against which the project's ACVP and cross-verification test vectors are pinned.
- **Hedged / randomised.** `sign_randomized` / `seal_randomized` draw a fresh 32-byte value from the system RNG on every call. The resulting signature verifies under the same public key as a deterministic one but differs byte-for-byte between calls.

Deterministic signing is vulnerable to fault-injection attacks: an adversary who can flip a single bit during the `z` computation can differentiate two signatures of the same message and recover `s1`/`s2` by lattice differential analysis. The hedged mode frustrates this attack because two signings of the same message use different internal randomness. Hardware wallets, cloud signers on untrusted silicon, and any deployment with a plausible fault-model should prefer the hedged entry points. SPHINCS+-256s robust is randomised-by-default per its parameter-set definition and does not expose a separate hedged mode.

### Memory hygiene

Every secret-bearing public type — `Seed`, `ExtendedSeed`, `MlDsa87`, `Dilithium`, `SphincsPlus256s`, `Xmss`, `MlDsa87Wallet`, `SphincsPlus256sWallet`, `LegacyXmssWallet` — implements `Drop` that zeroizes its backing buffer. Callers do not need to call `.zeroize()` explicitly for the scope-exit path to clear secrets from memory. Explicit `.zeroize()` is retained for long-lived signers that need to clear state mid-lifetime.

Accessor methods that return owned secret bytes (`seed`, `secret_key`, `secret_key_bytes`) return `zeroize::Zeroizing<T>`, so caller-held copies inherit the same drop-clear semantics. The owned wrapper dereferences transparently to the underlying byte array or `Vec<u8>` and works unchanged with `hex::encode`, `Sha256::digest`, `.iter()`, and the library's verify helpers.

After an explicit `.zeroize()`, a signer that is still reachable will not produce a bogus signature from the all-zero key: `sign`, `seal`, and the `*_with_secret_key` free functions return `QrllibError::MlDsaSecretKeyZeroized` / `DilithiumSecretKeyZeroized` / `SphincsPlusSecretKeyZeroized` / `XmssSecretKeyZeroized`.

### Browser surface (wasm)

The `qrllib-wasm` crate exposes two API shapes:

- **Handle-based (recommended).** `create_*_wallet`, `open_*_wallet`, `wallet_snapshot`, `wallet_sign`, `close_wallet`, `close_all_wallets`. The extended seed crosses the wasm/JS boundary exactly once (at `open_*_wallet` time); thereafter a plain `u32` handle is passed back and forth. `close_wallet` removes the registry entry, and the wallet's `Drop` zeroizes the in-wasm state. JavaScript strings never hold the seed between calls.
- **Legacy string-based.** `sign_message`, `sign_sphincsplus_message`, `sign_dilithium_message`, `sign_xmss_message`, and the paired `*_from_extended_seed_hex` / `generate_*` helpers. Retained for backwards compatibility. These re-accept the seed as a JavaScript string on every call; the seed persists in the JS heap across calls and cannot be zeroized from Rust. New browser consumers should prefer the handle-based API.

## Algorithm Notes

| Algorithm | Status | Notes |
|-----------|--------|-------|
| ML-DSA-87 | Primary | FIPS 204, NIST level 5, stateless |
| SPHINCS+-256s robust | Supported | Hash-based, stateless, pre-FIPS robust parameter set |
| Dilithium | Legacy | Pre-FIPS compatibility path |
| XMSS | Legacy | RFC 8391, stateful, QRL compatibility only |

## XMSS State Management

XMSS security is broken if the same OTS index is used twice.

The type system closes one failure mode: `Xmss` and `LegacyXmssWallet` deliberately do not implement `Clone`, so the accidental `wallet.clone()` path that would cause immediate one-time-key reuse is a compile error. This does **not** close the broader surface — serialising the secret-key bytes, persisting to disk, and re-instantiating later is a legitimate pattern that the library must support, and it is the application's responsibility to ensure the new instance starts at an OTS index greater than or equal to the highest used index.

Production XMSS usage must:

- Persist the updated index before using or broadcasting a signature.
- Maintain an append-only high-water mark for used indices.
- Reject concurrent signing from the same XMSS instance.
- Treat restored backups as unsafe until index history is reconciled.
- Rotate keys before exhausting the tree.

## Canonicality And Negative Testing

Rust regression suites cover malformed input, canonicality, KATs, thread-safety behavior, and legacy fuzz corpora:

- `crates/qrllib/tests/parity_suite.rs`
- `crates/qrllib/tests/kat_vectors.rs`
- `crates/qrllib/tests/thread_fuzz_suite.rs`
- `crates/qrllib/tests/acvp_mldsa.rs`
- `crates/qrllib/tests/rev_1_2_additions.rs` — regression coverage for the randomised-signing entry points, the `QrllibError::RejectionBudgetExceeded` variant, the lowercase-`q` address-validation tolerance, and the post-zeroize rejection of every sign/seal path (ML-DSA, Dilithium, SPHINCS+, and XMSS).

## Dependency Security

- Rust direct dependencies are exact-pinned in `Cargo.toml` and resolved in `Cargo.lock`; CI runs Cargo with `--locked`.
- Demo npm direct dependencies are exact-pinned in `package.json`; CI installs with `npm ci` from `package-lock.json`.
- GitHub Actions are pinned by commit SHA with version comments for auditability.
- `cargo audit` scans RustSec advisories.
- `cargo deny` enforces advisories, dependency bans, source policy, and license policy.
- Dependabot tracks Rust crates, demo npm dependencies, and GitHub Actions.

## Release Verification

All releases include checksums, SBOMs, and GitHub/Sigstore-backed attestations.

Verify release metadata with GitHub CLI:

```bash
gh attestation verify Cargo.toml --owner theQRL
gh attestation verify Cargo.lock --owner theQRL
gh attestation verify deny.toml --owner theQRL
gh attestation verify release-plz.toml --owner theQRL
gh attestation verify sbom-spdx.json --owner theQRL
```

Verify checksums:

```bash
curl -LO https://github.com/theqrl/rust-qrllib/releases/download/vX.Y.Z/checksums-sha256.txt
sha256sum -c checksums-sha256.txt
```

Verify SLSA provenance:

```bash
# Install slsa-verifier from https://github.com/slsa-framework/slsa-verifier
curl -LO https://github.com/theqrl/rust-qrllib/releases/download/vX.Y.Z/provenance.intoto.jsonl
slsa-verifier verify-artifact Cargo.toml \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/theqrl/rust-qrllib
```

Release artifacts:

| Artifact | Purpose |
|----------|---------|
| `Cargo.toml`, `Cargo.lock` | Workspace dependency state |
| `deny.toml`, `release-plz.toml` | Policy and release inputs |
| `checksums-sha256.txt`, `checksums-sha512.txt` | Integrity verification |
| `sbom-spdx.json`, `sbom-cyclonedx.json` | Software composition |
| `provenance.intoto.jsonl` | SLSA provenance |

## Secure Development Practices

Cryptographic changes require review, passing Rust CI, passing security checks, and no new unresolved warnings from `cargo clippy`, `cargo audit`, or `cargo deny`.
