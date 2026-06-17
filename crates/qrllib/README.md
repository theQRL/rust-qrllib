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
| XMSS (SHA2_10_256) | RFC 8391 | Stateful signature | [`Xmss`] |
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
use qrllib::{ML_DSA_87_CRYPTO_SEED_SIZE, MlDsa87, mldsa::verify_bytes};

// Use a CSPRNG to fill the seed in production code.
let seed = [0u8; ML_DSA_87_CRYPTO_SEED_SIZE];

let signer = MlDsa87::from_seed(seed);
let public_key = signer.public_key_bytes();

let context = b"my-app-v1";
let message = b"hello, post-quantum world";
let signature = signer.sign(context, message).expect("signing");

assert!(verify_bytes(context, message, &signature, &public_key).expect("verifying"));
```

See the [API docs](https://docs.rs/qrllib) for the wallet-level API
(`MlDsa87Wallet`, QRL addresses, mnemonics) and the other schemes.

## Feature flags

- **`experimental-sphincsplus-issuance`** *(off by default)* — gates the
  creation of new SPHINCS+ wallets. The implementation is the pre-FIPS-205
  SPHINCS+ submission; QRL has not yet committed to a specific SLH-DSA
  parameter set under FIPS 205, so issuing wallets is disabled by default to
  avoid locking users to a parameter set that may change. **Verification of
  existing SPHINCS+ signatures is always available** — only wallet creation is
  gated.

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

## License

Licensed under the [MIT License](LICENSE).
