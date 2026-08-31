# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in `rust-qrllib`, please report it responsibly:

1. Do not open a public issue.
2. Email security concerns to [security@theqrl.org](mailto:security@theqrl.org).
3. Or report via [https://www.theqrl.org/security-report/](https://www.theqrl.org/security-report/).
4. Include detailed steps to reproduce.
5. Allow reasonable time for a fix before public disclosure.

## Threat Model

### Assumptions

The library assumes:

- A trusted host, Rust toolchain, and JavaScript runtime for WASM consumers.
- A functioning operating-system CSPRNG for key generation, hedged signing, and
  randomized encapsulation.
- Callers authenticate the data and protocol context they intend to sign.
- XMSS callers maintain one durable, monotonic OTS-index authority per key.

### What the library protects against

- Signature forgery under the security assumptions of the configured scheme.
- Malformed public inputs reaching unchecked public API paths: wrong lengths and
  unsupported identifiers return typed errors or verification failure.
- Accidental reuse of one in-memory XMSS signer through cloning or concurrent
  mutable access in safe Rust.
- Residual secret material in owned Rust buffers after normal drop, on a
  best-effort basis described below.

### What the library does not protect against

- Compromised hosts, malicious dependencies or toolchains, physical memory
  probing, swap/hibernation capture, or side-channel-capable co-tenants.
- Weak or subverted system randomness.
- Application-level replay, authorization, rate limiting, transaction intent,
  or display/UI substitution attacks.
- XMSS index reuse across processes, devices, database rollbacks, or restored
  backups.
- Copies of secrets made by callers, debuggers, serializers, the JavaScript
  engine, or the browser before Rust zeroization runs.

### Signing modes (ML-DSA-87)

ML-DSA-87 is **hedged by default** per FIPS 204 §3.4 — the FIPS-recommended mode (TOB-QRLLIB-6):

- **Hedged (default).** `sign` / `sign_attached` draw a fresh 32-byte value from the system RNG on every call. Two signs of the same `(secret_key, [context,] message)` produce **distinct** signature bytes; both verify under the same public key. Verification is unchanged and existing verifiers — on-chain or off — are unaffected.
- **Deterministic (FIPS 204 §3.5 opt-in).** `sign_deterministic` / `sign_attached_deterministic` use a fixed all-zero per-signature value, so the same `(secret_key, [context,] message)` always yields byte-identical signatures. **Use only when the deterministic property is itself a security or protocol requirement** — for example, RANDAO-style verifiable beacon contributions where each validator must produce the same signature for the same input, or ACVP / KAT test-vector reproduction.

Deterministic signing is vulnerable to fault-injection attacks: an adversary who can flip a single bit during the `z` computation can differentiate two signatures of the same message and recover `s1`/`s2` by lattice differential analysis. Hedged signing frustrates this attack because two signings of the same message use different internal randomness. SPHINCS+-256s robust is randomised-by-default per its parameter-set definition and does not expose a separate deterministic mode.

The free signing function `sign_with_secret_key` (ML-DSA-87) follows the same convention: hedged by default, with `sign_with_secret_key_deterministic` as the explicit opt-in. ACVP, KAT, and cross-verification test vectors that pin specific signature bytes route through the deterministic entry points.

### Memory hygiene

Every secret-bearing public type — `Seed`, `ExtendedSeed`, `MlDsa87`, `SphincsPlus256s`, `Xmss`, `MlDsa87Wallet`, `SphincsPlus256sWallet`, `LegacyXmssWallet` — implements `Drop` that zeroizes its backing buffer. Callers do not need to call `.zeroize()` explicitly for the scope-exit path to clear secrets from memory. Explicit `.zeroize()` is retained for long-lived signers that need to clear state mid-lifetime.

Accessor methods that return owned secret bytes (`seed`, `secret_key`, `secret_key_bytes`) return `zeroize::Zeroizing<T>`, so caller-held copies inherit the same drop-clear semantics. The owned wrapper dereferences transparently to the underlying byte array or `Vec<u8>` and works unchanged with `hex::encode`, `Sha256::digest`, `.iter()`, and the library's verify helpers.

After an explicit `.zeroize()`, a signer that is still reachable will not produce a bogus signature from the all-zero key: `sign`, `sign_attached`, and the `*_with_secret_key` free functions return `QrllibError::MlDsaSecretKeyZeroized` / `SphincsPlusSecretKeyZeroized` / `XmssSecretKeyZeroized`.

#### Guarantee boundary

Zeroization is defense in depth, not proof that no secret copy remains. Rust may
move values, allocator pages may retain prior contents, optimized code and FFI
may create copies, and operating systems may page memory to disk. `zeroize`
provides volatile writes and compiler fences for the buffers it owns; it cannot
wipe copies outside those buffers. WASM adds a second boundary: Rust can clear
linear-memory state, but JavaScript strings are immutable and cannot be
reliably erased.

Use an HSM or equivalent protected execution environment where process-memory
zeroization is not a sufficient control.

### API Precondition Guarantees

Every exported function in `crates/qrllib/src/` is documented with the precondition contract it enforces. The Rust type system carries most of these by construction; the table below names the contracts a reader coming from the Go-side audit would expect to find (TOB-QRLLIB cross-cutting item: precondition validation at every exported API entry point).

| Surface | Contract |
|---------|----------|
| Public-key references | All verify / open entry points take `&[u8]` or `&[u8; N]` — neither can be null in safe Rust (vs the Go-side TOB-11 nil-pk dereference class). |
| Wrong-size buffer inputs | Length-validating constructors return `Err(QrllibError::Invalid*Size(actual, expected))` rather than panicking; the variant names are stable. |
| Parameter-set identifiers | `WalletType`, `XmssHashFunction`, `XmssHeight` are sum-type enums / validated newtypes constructed via `TryFrom<u8>` / `new(value)`; invalid bytes return typed errors (`QrllibError::UnknownWalletType`, `QrllibError::InvalidXmssHashFunction`, `QrllibError::InvalidXmssHeight`). There is no safe-Rust way to construct an out-of-range instance. |
| Wallet issuance gating | Every `SphincsPlus256sWallet` constructor returns `Err(QrllibError::WalletTypeNotIssuable(...))` unless `experimental-sphincsplus-issuance` (or `cfg(test)`) is set (TOB-QRLLIB-4). `WalletType::SphincsPlus256s` is `is_valid() == is_issuable() == is_verifiable() == false`, so `Descriptor::is_valid()` rejects the SPHINCS+ descriptor and `get_address` / `ExtendedSeed` / `verify_sphincsplus_wallet_signature` refuse it, matching go-qrllib's `wallettype` and `descriptor` gates. |
| Stateful XMSS index | `Xmss` and `LegacyXmssWallet` do **not** implement `Clone`; accidental duplication that would cause OTS index reuse is a compile error. Index persistence remains the caller's responsibility — see `Xmss::sign` rustdoc and the "XMSS State Management" section above. |
| Secret-bearing types | `Drop` zeroizes; accessor methods returning owned secret bytes wrap them in `zeroize::Zeroizing<T>`. Post-`.zeroize()` re-use surfaces `QrllibError::*SecretKeyZeroized` rather than producing a bogus signature. |
| Signing mode | `sign` / `sign_attached` are hedged by default per FIPS 204 §3.4 (TOB-QRLLIB-6); `sign_deterministic` / `sign_attached_deterministic` are the explicit opt-in for protocols that need byte-identical signatures. |
| Panic policy | Production code panics **only** on invariant violations that mark a regression in upstream validation (currently the single `chunks_exact(4)` tripwire in `sphincsplus::bytes_to_addr`); malformed user input always returns a typed `Result::Err`. |

### Audit-derived design choices (mapping from `go-qrllib` Trail of Bits findings)

The Trail of Bits audit was scoped to the Go implementation (`go-qrllib`). Several of its findings have no Rust-port analogue because the Rust port's type system, ownership model, or API surface already eliminates the failure mode. They are recorded here so a reader coming from the Go advisory can see the Rust-side reasoning:

- **Invalid XMSS hash-function values (TOB-QRLLIB-13).** The Go advisory describes a path where `xmss.HashFunction(99)` — a raw integer cast that bypasses the validating constructor — reaches `coreHash`'s dispatch switch, falls through the missing `default`, leaves the output buffer zero-initialised, and produces a degenerate zero-rooted XMSS whose signatures cross-verify with each other's public keys. The Rust port's [`XmssHashFunction`](crates/qrllib/src/xmss.rs) is a closed `enum` constructed via `TryFrom<u8>`, which returns `QrllibError::InvalidXmssHashFunction(value)` on any byte outside `{0, 1, 2}`. There is no safe-Rust way to instantiate an out-of-range `XmssHashFunction`, so the attack vector cannot exist at the type-system level.
- **Nil public-key dereferences (TOB-QRLLIB-11).** All Rust verify / open entry points take `&[u8]` slices or fixed-size `&[u8; N]` array references, neither of which can be null in safe Rust. The Go-side nil-pk guard requirements have no Rust analogue.
- **`Open` collapsing distinct failure modes into `nil` (TOB-QRLLIB-14).** Rust verify / open helpers already return `Result<…, QrllibError>` or `Option<&[u8]>` per idiomatic Rust error handling. The Go-side rewrite to typed sentinels is already-by-construction in Rust.
- **Inconsistent ML-DSA secret-material zeroisation (TOB-QRLLIB-10).** Every secret-bearing public type implements `Drop` that zeroizes its backing buffer, and accessors that return owned secret bytes wrap them in `zeroize::Zeroizing<T>` so callers inherit the same clear-on-drop semantics (see the **Memory hygiene** section above).
- **XMSS height accepts out-of-range values (TOB-QRLLIB-2).** [`XmssHeight`](crates/qrllib/src/xmss.rs) is a validated newtype constructed via `XmssHeight::new(value)`, which returns `QrllibError::InvalidXmssHeight(value)` on any value outside the allowed range; the validating constructor is the only way to obtain an `XmssHeight`.

Go-side findings that do apply to Rust are recorded in the affected rustdoc and
covered by `crates/qrllib/tests/audit_remediation_suite.rs` and the focused
hardening tests; references retain the relevant TOB-QRLLIB identifier.

### Browser surface (wasm)

The `qrllib-wasm` crate exposes two API shapes:

- **Handle-based (recommended).** `create_*_wallet`, `open_*_wallet`, `wallet_snapshot`, `wallet_sign`, `close_wallet`, `close_all_wallets`. The extended seed crosses the wasm/JS boundary exactly once (at `open_*_wallet` time); thereafter a plain `u32` handle is passed back and forth. `close_wallet` removes the registry entry, and the wallet's `Drop` zeroizes the in-wasm state. JavaScript strings never hold the seed between calls.
- **Legacy string-based.** `sign_message`, `sign_sphincsplus_message`, `sign_xmss_message`, and the paired `*_from_extended_seed_hex` / `generate_*` helpers. Retained for backwards compatibility. These re-accept the seed as a JavaScript string on every call; the seed persists in the JS heap across calls and cannot be zeroized from Rust. New browser consumers should prefer the handle-based API.

## Algorithm Notes

| Algorithm | Status | State | Signing / failure behavior | Notes |
|-----------|--------|-------|----------------------------|-------|
| ML-DSA-87 | Primary | Stateless | Hedged by default; deterministic opt-in | FIPS 204, NIST level 5 |
| ML-KEM-1024 | Supported | Stateless | Implicit rejection returns a pseudorandom shared secret for a correct-length invalid ciphertext; wrong lengths return a typed error | FIPS 203 KEM; standalone, not wallet-integrated |
| SPHINCS+-256s robust | Supported primitive | Stateless | Randomized signing | SPHINCS+ submission parameter set, not FIPS 205 SLH-DSA; wallet issuance **and** verification gated by default |
| XMSS | Legacy migration only | **Stateful** | Deterministic; OTS index must never repeat | QRL compatibility construction; see the provenance notes in README |

### XMSS provenance and standards alignment

QRL deployed its XMSS construction before [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html)
was published in May 2018. The eventual RFC specified a construction
that is closely aligned with QRL for the overlapping SHA2-256 and SHAKE256
parameter families. In particular, their signature byte layout is compatible,
and RFC 8391 section 3.1.7 permits pseudorandom private-key generation while
giving `PRF(seed, toByte(i, 32))` as an example. That example matches the
private WOTS-string derivation retained by QRL.

This history matters because XMSS roots form part of QRL v1 public keys and
addresses on an immutable blockchain. Replacing the deployed derivation would
not transparently upgrade an existing key: it would derive a different tree
root and therefore a different address. Preserving the construction is a
consensus-compatibility requirement, not an attempt to retrofit a later
profile onto historical keys.

The compatibility surface has explicit boundaries:

- `Sha2_256` and `Shake256` use the RFC 8391 signature construction for the
  overlapping `n=32` parameter families. The `xmss::rfc8391` module maps the
  six supported height-10/16/20 OIDs and converts between QRL's three-byte
  descriptor/public-key convention and the RFC's four-byte OID layout.
- The external CI test proves both signing directions against the pinned XMSS
  reference for `XMSS-SHA2_10_256`: Rust signs and the reference verifies, then
  the reference signs from the same 96-byte expanded seed and Rust verifies.
  The adapter maps the other supported OIDs, but the workflow does not claim
  independent reference coverage for every mapped parameter set.
- QRL's 48-byte seed is SHAKE256-expanded into `SK_SEED || SK_PRF || PUB_SEED`.
  RFC 8391 does not prescribe that outer wallet-seed convention; the interop
  module therefore also accepts the 96 bytes directly.
- `Shake128` is a pre-standardisation QRL-specific variant with no RFC OID. It
  remains available only so existing v1 addresses can be parsed, verified, and
  signed; it is not recommended for new keys.

[NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final), published in
October 2020, is a later and deliberately stricter profile of stateful
hash-based signatures. Following public analysis of multi-target security, it
selected `PRFkeygen(SK_SEED, PUB_SEED || ADRS)` for private-string generation.
It also restricts approved parameter sets and requires key and signature
generation in non-exporting hardware cryptographic modules. Those requirements
post-date QRL's deployed keys and are not this library's compatibility target.
Accordingly, `rust-qrllib` should not be represented as an SP 800-208-conforming
cryptographic module. That scope statement does not mean QRL signatures are
malformed: for the overlapping construction they retain RFC-format
interoperability as described and tested above.

The cross-verification workflow pins `xmss-reference` commit `7793c40`, the
last revision using the compatible RFC-example derivation. Upstream commit
[`3e28db2`](https://github.com/XMSS/xmss-reference/commit/3e28db2) subsequently
introduced the SP 800-208-style `PRFkeygen` construction. The pin is therefore
intentional and auditable rather than an untracked dependency on an old
revision.

## Address Security

Modern QRL addresses are 64 bytes:

```text
SHAKE256(descriptor || public_key)[:64]
```

Their string form is an uppercase `Q` followed by 128 hexadecimal characters.
`format_address` emits lowercase hex; `to_checksum_address` emits the canonical
EIP-55-style mixed-case checksum used by `go-qrllib` and wallet.js.

`is_valid_address` is permissive about the **hex body** only: it accepts
uniform-case input or a correctly checksummed mixed-case form. The `Q` prefix
must be uppercase, so `rust-qrllib` and `go-qrllib` accept exactly the same set
of address strings. Applications that require typo
detection should use `is_valid_checksum_address`. The checksum is not an
authentication mechanism; an attacker who controls the display path can show a
valid checksum for an attacker-controlled address.

## Side-channel boundary

The ML-DSA verification challenge comparison and ML-KEM re-encryption check use
full-width constant-time equality helpers. ML-KEM decapsulation performs
implicit rejection without branching on ciphertext validity. These properties
do not make the whole library, Rust standard library, allocator, browser, or CPU
constant-time.

Signing includes parameter-defined rejection sampling, and execution time may
vary with public inputs, random nonces, runtime scheduling, cache state, and the
target platform. Deployments requiring hardware-level resistance to local
timing, cache, fault-injection, or memory attacks should use an independently
evaluated hardened implementation or HSM.

## XMSS State Management

XMSS security is broken if the same OTS index is used twice.

The type system closes one failure mode: `Xmss` and `LegacyXmssWallet` deliberately do not implement `Clone`, so the accidental `wallet.clone()` path that would cause immediate one-time-key reuse is a compile error. This does **not** close the broader surface — serialising the secret-key bytes, persisting to disk, and re-instantiating later is a legitimate pattern that the library must support, and it is the application's responsibility to ensure the new instance starts at an OTS index greater than or equal to the highest used index.

Production XMSS usage must:

- Persist the updated index before using or broadcasting a signature.
- Maintain an append-only high-water mark for used indices.
- Reject concurrent signing from the same XMSS instance.
- Treat restored backups as unsafe until index history is reconciled.
- Rotate keys before exhausting the tree.

The required ordering is:

```text
1. Generate the signature; the in-memory index advances.
2. Persist the new high-water mark to durable, monotonic storage.
3. Verify that persistence succeeded.
4. Only then release or broadcast the signature.
```

| Failure mode | Consequence | Required control |
|--------------|-------------|------------------|
| Process or power loss before persistence | The previous index may be loaded again | Never release the signature before the new index is durable |
| Concurrent signers | Two instances may consume the same index | One serialized signing authority per key |
| Backup or snapshot restore | Stored state can move backwards | Reconcile against an external append-only high-water mark |
| Database rollback | Used indices can reappear as available | Monotonic or append-only storage with rollback detection |
| Tree exhaustion | No unused OTS keys remain | Monitor capacity and rotate early |

## Canonicality And Negative Testing

Rust regression suites cover malformed input, canonicality, KATs, thread-safety behavior, and legacy fuzz corpora:

- `crates/qrllib/tests/parity_suite.rs`
- `crates/qrllib/tests/kat_vectors.rs`
- `crates/qrllib/tests/thread_fuzz_suite.rs`
- `crates/qrllib/tests/acvp_mldsa.rs`
- `crates/qrllib/tests/mlkem_cross_vectors.rs` — ML-KEM-1024 key generation, encapsulation, and decapsulation cross-verified byte-for-byte against `go-qrllib`.
- ML-KEM-1024 NIST ACVP keyGen + encapDecap (the `acvp` module in `crates/qrllib/src/mlkem.rs`) and the C2SP/wycheproof + C2SP/CCTV corpora (`crates/qrllib/tests/wycheproof_mlkem.rs`), consumed from upstream at CI time. See `.github/acvp/README.md` and `.github/wycheproof/README.md`.
- `crates/qrllib/tests/hardening_suite.rs` — regression coverage for the randomised-signing entry points, the `QrllibError::RejectionBudgetExceeded` variant, the uppercase-`Q` address-prefix requirement, and the post-zeroize rejection of every sign/seal path (ML-DSA, SPHINCS+, and XMSS).

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
curl -LO https://github.com/theQRL/rust-qrllib/releases/download/qrllib-vX.Y.Z/checksums-sha256.txt
sha256sum -c checksums-sha256.txt
```

Verify SLSA provenance:

```bash
# Install slsa-verifier from https://github.com/slsa-framework/slsa-verifier
curl -LO https://github.com/theQRL/rust-qrllib/releases/download/qrllib-vX.Y.Z/provenance.intoto.jsonl
slsa-verifier verify-artifact Cargo.toml \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/theQRL/rust-qrllib
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

## Version Support

| Version | Support |
|---------|---------|
| Latest release | Full support |
| Previous minor release | Security fixes where practical |
| Older releases | Unsupported; upgrade to the latest release |

## Contact

For security concerns, email [security@theqrl.org](mailto:security@theqrl.org)
or use the [QRL security report form](https://www.theqrl.org/security-report/).
