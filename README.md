# rust-qrllib

Rust implementation of the Quantum Resistant Ledger cryptographic library, with native Rust APIs and wasm-bindgen bindings for browser use.

[![codecov](https://codecov.io/gh/theqrl/rust-qrllib/branch/main/graph/badge.svg)](https://codecov.io/gh/theqrl/rust-qrllib)

## Overview

`rust-qrllib` provides post-quantum signature schemes and QRL wallet/address helpers for native Rust and WebAssembly consumers.

Supported algorithms:

| Algorithm | Type | Standard | Use case |
|-----------|------|----------|----------|
| ML-DSA-87 | Lattice-based | FIPS 204 | Primary stateless signature scheme |
| Dilithium | Lattice-based | Pre-FIPS | Legacy compatibility |
| SPHINCS+-256s robust | Hash-based | SPHINCS+ pre-FIPS | Conservative stateless signatures |
| XMSS | Hash-based | RFC 8391 | Legacy QRL address compatibility |

## Workspace

| Path | Purpose |
|------|---------|
| `crates/qrllib` | Core Rust library |
| `crates/qrllib-wasm` | wasm-bindgen wrappers for browser use |
| `demo` | Vue + Tailwind demo app using the compiled wasm package |
| `.github/workflows` | Rust-native CI, ACVP, cross-verification, release, security, and demo deployment workflows |

## Native Rust API

Until the first crates.io release, consume the core library as a workspace/path dependency:

```toml
[dependencies]
qrllib = { path = "crates/qrllib" }
```

After publication, this becomes:

```toml
[dependencies]
qrllib = "0.1"
```

Generate the complete Rust API reference locally:

```bash
cargo doc -p qrllib --no-deps --open
```

### Wallet-Level API

Wallet APIs include QRL descriptors, address derivation, seeds, extended seeds, mnemonics, signing, and wallet-specific verification.

| API | Purpose |
|-----|---------|
| `MlDsa87Wallet` | ML-DSA-87 QRL wallet wrapper |
| `SphincsPlus256sWallet` | SPHINCS+-256s robust QRL wallet wrapper |
| `LegacyXmssWallet` | Legacy XMSS QRL wallet wrapper |
| `verify_mldsa87_wallet_signature` | Verify ML-DSA-87 wallet signatures with descriptor binding |
| `verify_sphincsplus_wallet_signature` | Verify SPHINCS+ wallet signatures with descriptor binding |
| `verify_legacy_xmss` | Verify legacy XMSS signatures |

Common wallet construction/restoration methods:

| Type | Constructors |
|------|--------------|
| `MlDsa87Wallet` | `generate`, `from_seed`, `from_hex_seed`, `from_extended_seed`, `from_hex_extended_seed`, `from_mnemonic` |
| `SphincsPlus256sWallet` | `generate`, `from_seed`, `from_hex_seed`, `from_extended_seed`, `from_hex_extended_seed`, `from_mnemonic` |
| `LegacyXmssWallet` | `new`, `new_from_seed`, `new_from_extended_seed` |

Common wallet accessors:

| Type | Accessors |
|------|-----------|
| `MlDsa87Wallet` | `seed`, `extended_seed`, `hex_seed`, `mnemonic`, `descriptor`, `public_key`, `secret_key`, `address`, `address_string`, `sign`, `zeroize` |
| `SphincsPlus256sWallet` | `seed`, `extended_seed`, `hex_seed`, `mnemonic`, `descriptor`, `public_key`, `secret_key`, `address`, `address_string`, `sign`, `seal`, `zeroize` |
| `LegacyXmssWallet` | `height`, `seed`, `extended_seed`, `hex_seed`, `mnemonic`, `root`, `public_key`, `secret_key`, `address`, `index`, `set_index`, `sign`, `descriptor`, `zeroize` |

ML-DSA-87 wallet round trip:

```rust
use qrllib::{MlDsa87Wallet, Seed, verify_mldsa87_wallet_signature};

fn main() -> Result<(), qrllib::QrllibError> {
    let seed = Seed::generate()?;
    let wallet = MlDsa87Wallet::from_seed(seed)?;
    let message = b"The sleeper must awaken";
    let signature = wallet.sign(message)?;

    let ok = verify_mldsa87_wallet_signature(
        message,
        &signature,
        &wallet.public_key(),
        wallet.descriptor(),
    );

    assert!(ok);
    Ok(())
}
```

SPHINCS+-256s wallet round trip:

```rust
use qrllib::{Seed, SphincsPlus256sWallet, verify_sphincsplus_wallet_signature};

fn main() -> Result<(), qrllib::QrllibError> {
    let wallet = SphincsPlus256sWallet::from_seed(Seed::generate()?)?;
    let message = b"hash-based signatures";
    let signature = wallet.sign(message)?;

    assert!(verify_sphincsplus_wallet_signature(
        message,
        &signature,
        &wallet.public_key(),
        wallet.descriptor(),
    ));

    Ok(())
}
```

Legacy XMSS wallet round trip:

```rust
use qrllib::{LegacyXmssWallet, XmssHashFunction, XmssHeight, verify_legacy_xmss};

fn main() -> Result<(), qrllib::QrllibError> {
    let mut wallet = LegacyXmssWallet::new(
        XmssHeight::new(4)?,
        XmssHashFunction::Shake128,
    )?;
    let message = b"stateful signing";
    let signature = wallet.sign(message)?;

    assert!(verify_legacy_xmss(message, &signature, wallet.public_key()));

    // Persist wallet.index() before using or broadcasting the signature.
    Ok(())
}
```

### Low-Level Signer API

Low-level signers are available for callers that do not need wallet descriptors, addresses, mnemonics, or QRL seed formats.

| API | Purpose |
|-----|---------|
| `MlDsa87` | FIPS 204 ML-DSA-87 signer with context-aware signing |
| `SphincsPlus256s` | SPHINCS+-SHAKE-256s-robust signer |
| `Dilithium` | Legacy CRYSTALS-Dilithium Round 3 compatibility signer |
| `Xmss` | Lower-level RFC 8391 XMSS tree signer |

Common low-level methods:

| Type | Constructors and accessors |
|------|---------------------------|
| `MlDsa87` | `generate`, `from_seed`, `from_hex_seed`, `public_key_bytes`, `secret_key_bytes`, `seed`, `hex_seed`, `sign`, `seal`, `verify`, `zeroize` |
| `SphincsPlus256s` | `generate`, `from_seed`, `from_hex_seed`, `public_key_bytes`, `secret_key_bytes`, `seed`, `hex_seed`, `sign`, `seal`, `zeroize` |
| `Dilithium` | `generate`, `from_seed`, `from_hex_seed`, `public_key_bytes`, `secret_key_bytes`, `seed`, `hex_seed`, `sign`, `seal`, `verify`, `zeroize` |
| `Xmss` | `initialize_tree`, `seed`, `secret_key`, `public_seed`, `root`, `public_key`, `hash_function`, `height`, `index`, `set_index`, `sign`, `zeroize` |

Low-level verification and sealed-message helpers:

| API | Purpose |
|-----|---------|
| `mldsa::verify_bytes` | Verify ML-DSA-87 with explicit FIPS 204 context |
| `sign_mldsa_with_secret_key` | Stateless ML-DSA-87 secret-key signing with explicit FIPS 204 context |
| `open`, `extract_message`, `extract_signature` | ML-DSA-87 sealed-message helpers |
| `verify_sphincsplus_signature` | Verify detached SPHINCS+ signatures |
| `sphincsplus_open`, `sphincsplus_extract_message`, `sphincsplus_extract_signature` | SPHINCS+ sealed-message helpers |
| `verify_dilithium_signature` | Verify detached legacy Dilithium signatures |
| `sign_dilithium_with_secret_key` | Stateless legacy Dilithium secret-key signing |
| `dilithium_open`, `dilithium_extract_message`, `dilithium_extract_signature` | Dilithium sealed-message helpers |
| `verify_xmss`, `verify_xmss_with_custom_wots_param_w` | Verify lower-level XMSS signatures |

### Common Types And Utilities

| API | Purpose |
|-----|---------|
| `Seed` | 48-byte QRL seed with generation, hex parsing, hashing, and zeroization |
| `ExtendedSeed` | Descriptor plus seed bytes for deterministic wallet restoration |
| `Descriptor` | 3-byte descriptor used in modern QRL address/wallet formats |
| `WalletType` | Modern wallet algorithm identifier |
| `QrlDescriptor` | Legacy XMSS descriptor |
| `XmssHashFunction`, `XmssHeight` | XMSS parameter types |
| `format_address`, `get_address`, `is_valid_address` | Modern QRL address helpers |
| `get_xmss_address_from_pk`, `is_valid_xmss_address` | Legacy XMSS address helpers |
| `bin_to_mnemonic`, `mnemonic_to_bin` | QRL wordlist conversion helpers |
| `QrllibError`, `Result` | Shared error and result types |

## WebAssembly API

`crates/qrllib-wasm` wraps the Rust API with `wasm-bindgen` for browser use. It is currently marked `publish = false` as a Rust crate and is built into a JavaScript package with `wasm-pack`.

Build the package:

```bash
wasm-pack build crates/qrllib-wasm --target web --out-dir pkg
```

For npm publication, build with the QRL scope:

```bash
wasm-pack build crates/qrllib-wasm --target web --release --scope theqrl --out-dir pkg
```

`wasm-pack` emits JavaScript glue and TypeScript declarations in `crates/qrllib-wasm/pkg`.

### Wasm Return Shapes

Wallet functions return a wallet snapshot:

```ts
type WalletSnapshot = {
  scheme: 'ml-dsa-87' | 'sphincsplus-256s' | 'legacy-xmss'
  address: string
  descriptorHex: string
  extendedSeedHex: string
  mnemonic: string
  publicKeyHex: string
  rawSeedHex: string
  xmssHashFunction?: string | null
  xmssHeight?: number | null
  xmssIndex?: number | null
}
```

Signing functions return a signature snapshot:

```ts
type SignatureSnapshot = {
  scheme: 'ml-dsa-87' | 'sphincsplus-256s' | 'legacy-xmss' | 'legacy-dilithium'
  signatureHex: string
  verified: boolean
  xmssIndex?: number | null
  xmssNextIndex?: number | null
}
```

Legacy Dilithium generation/restoration returns:

```ts
type DilithiumSnapshot = {
  scheme: 'legacy-dilithium'
  seedHex: string
  publicKeyHex: string
}
```

### Wasm Function Map

| Function | Purpose |
|----------|---------|
| `generate_wallet()` | Generate an ML-DSA-87 wallet snapshot |
| `wallet_from_extended_seed_hex(extendedSeedHex)` | Restore an ML-DSA-87 wallet snapshot |
| `sign_message(extendedSeedHex, message)` | Sign with ML-DSA-87 wallet material |
| `verify_message(publicKeyHex, descriptorHex, message, signatureHex)` | Verify an ML-DSA-87 wallet signature |
| `generate_sphincsplus_wallet()` | Generate a SPHINCS+-256s wallet snapshot |
| `sphincsplus_wallet_from_extended_seed_hex(extendedSeedHex)` | Restore a SPHINCS+-256s wallet snapshot |
| `sign_sphincsplus_message(extendedSeedHex, message)` | Sign with SPHINCS+ wallet material |
| `verify_sphincsplus_message(publicKeyHex, descriptorHex, message, signatureHex)` | Verify a SPHINCS+ wallet signature |
| `generate_dilithium_signer()` | Generate a legacy Dilithium signer snapshot |
| `dilithium_from_hex_seed(seedHex)` | Restore a legacy Dilithium signer snapshot |
| `sign_dilithium_message(seedHex, message)` | Sign with legacy Dilithium seed material |
| `verify_dilithium_message(publicKeyHex, message, signatureHex)` | Verify a legacy Dilithium signature |
| `generate_xmss_wallet(height, hashFunction)` | Generate a legacy XMSS wallet snapshot |
| `xmss_wallet_from_extended_seed_hex(extendedSeedHex, index)` | Restore an XMSS wallet snapshot at an explicit OTS index |
| `sign_xmss_message(extendedSeedHex, index, message)` | Sign with legacy XMSS and return the next OTS index |
| `verify_xmss_message(publicKeyHex, message, signatureHex)` | Verify a legacy XMSS signature |

Supported XMSS `hashFunction` strings are `sha2_256`, `shake128`, and `shake256`.

### Browser Usage

```ts
import init, {
  generate_wallet,
  sign_message,
  verify_message,
} from './pkg/qrllib_wasm'

await init()

const wallet = generate_wallet()
const signed = sign_message(wallet.extendedSeedHex, 'The sleeper must awaken')
const ok = verify_message(
  wallet.publicKeyHex,
  wallet.descriptorHex,
  'The sleeper must awaken',
  signed.signatureHex,
)

console.assert(ok)
```

The Vue demo keeps a typed wrapper in `demo/src/qrllib.ts` that mirrors the wasm exports.

## Browser Demo

The demo builds the wasm package locally before Vite compiles the Vue app.

```bash
cd demo
npm install
npm run build
```

For local development:

```bash
cd demo
npm run dev
```

The GitHub Pages workflow builds the same app and publishes `demo/dist`.

## XMSS Statefulness Warning

XMSS is stateful. Reusing an XMSS OTS index can completely break signature security.

Safe XMSS usage requires:

- Never reuse an index.
- Persist the updated index before using or broadcasting a signature.
- Never sign concurrently from the same XMSS wallet.
- Never restore a wallet from backup without validating the highest used index.
- Rotate keys before the tree is exhausted.

For new applications, prefer ML-DSA-87 or SPHINCS+-256s robust.

## Verification

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo llvm-cov --package qrllib --summary-only
cd demo && npm run build
```

Additional CI coverage:

- ML-DSA-87 is an in-repo Rust port of the `go-qrllib` implementation, not a wrapper around a packaged ML-DSA crate.
- ML-DSA-87 ACVP vectors are pulled from NIST ACVP-Server at workflow runtime.
- Dilithium, ML-DSA-87, SPHINCS+, and XMSS are cross-verified against external reference implementations.
- `cargo audit` and `cargo deny` enforce supply-chain checks.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, algorithm notes, release verification, SBOMs, and attestation details.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
