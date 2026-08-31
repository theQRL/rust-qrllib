# qrllib

[![crates.io](https://img.shields.io/crates/v/qrllib.svg)](https://crates.io/crates/qrllib)
[![docs.rs](https://docs.rs/qrllib/badge.svg)](https://docs.rs/qrllib)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust implementation of the [QRL](https://www.theqrl.org/) (Quantum Resistant
Ledger) cryptographic primitives, wallet helpers, and address format — a
faithful port of [`go-qrllib`](https://github.com/theqrl/go-qrllib), usable from
both native and WebAssembly targets.

## Schemes

| Scheme | Standard | Type | Entry point |
|---|---|---|---|
| ML-DSA-87 | FIPS 204 | Signature | [`MlDsa87`] |
| ML-KEM-1024 | FIPS 203 | KEM | [`DecapsulationKey`] / [`EncapsulationKey`] |
| SPHINCS+-256s | pre-FIPS-205 submission | Signature | [`SphincsPlus256s`] |
| XMSS | Predates RFC 8391; **not** a standards-tracking implementation. Signatures are wire-compatible with the RFC 8391 reference only where the parameter sets overlap (`Sha2_256` / `Shake256`, via the `xmss::rfc8391` adapter); `Shake128` is a QRL-specific pre-standardisation variant with no RFC counterpart. Does not track NIST SP 800-208. | Stateful signature | [`Xmss`] |
| Legacy XMSS | QRL v1 | Migration shim | [`LegacyXmssWallet`] |

Plus QRL wallet, address, descriptor, mnemonic, and seed helpers
(`MlDsa87Wallet`, `get_address`, `bin_to_mnemonic`, `ExtendedSeed`, …).

## Usage

```toml
[dependencies]
qrllib = "0.1"
```

Sign and verify with ML-DSA-87:

```rust
use qrllib::{MlDsa87, mldsa::verify_bytes};

fn main() -> Result<(), qrllib::QrllibError> {
    let signer = MlDsa87::generate()?;
    let public_key = signer.public_key_bytes();

    let context = b"my-app-v1";
    let message = b"hello, post-quantum world";
    let signature = signer.sign(context, message)?;

    assert!(verify_bytes(context, message, &signature, &public_key)?);
    Ok(())
}
```

See the [API docs](https://docs.rs/qrllib) for the wallet-level API
(`MlDsa87Wallet`, QRL addresses, mnemonics) and the other schemes.

## Feature flags

- **`experimental-sphincsplus-issuance`** *(off by default)* — gates the
  SPHINCS+ **wallet path**, both creation and verification. The implementation
  is the pre-FIPS-205 SPHINCS+ submission; QRL has not yet committed to a
  specific SLH-DSA parameter set under FIPS 205, so the path is disabled by
  default to avoid locking users to a parameter set that may change. No
  SPHINCS+ signatures exist on QRL networks, so `verify_sphincsplus_wallet_signature`
  returns `false` without this feature, matching go-qrllib. The **raw
  `SphincsPlus256s` primitive** (`sign` / `verify_sphincsplus_signature`,
  outside the wallet layer) stays unrestricted.

## Validation

The implementations are checked for byte-level correctness against:

- Reference implementations via CI cross-verification — pq-crystals (ML-DSA-87),
  the SPHINCS+ reference, and the XMSS reference.
- NIST ACVP test vectors (ML-DSA-87, ML-KEM-1024).
- Project Wycheproof and C2SP/CCTV vectors (ML-KEM-1024).

## Security

This crate handles cryptographic key material. See
[`SECURITY.md`](https://github.com/theQRL/rust-qrllib/blob/main/SECURITY.md)
in the repository for the security policy, standards-alignment notes, and how to
report vulnerabilities.

> **XMSS is stateful.** Persist the advanced index before using a signature and
> never allow two processes or restored copies to sign from the same index.
> Prefer ML-DSA-87 for new applications.

## License

Licensed under the [MIT License](https://github.com/theQRL/rust-qrllib/blob/main/LICENSE).
