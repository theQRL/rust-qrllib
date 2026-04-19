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

## Algorithm Notes

| Algorithm | Status | Notes |
|-----------|--------|-------|
| ML-DSA-87 | Primary | FIPS 204, NIST level 5, stateless |
| SPHINCS+-256s robust | Supported | Hash-based, stateless, pre-FIPS robust parameter set |
| Dilithium | Legacy | Pre-FIPS compatibility path |
| XMSS | Legacy | RFC 8391, stateful, QRL compatibility only |

## XMSS State Management

XMSS security is broken if the same OTS index is used twice.

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

## Dependency Security

- Rust dependencies are pinned in `Cargo.lock`.
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
