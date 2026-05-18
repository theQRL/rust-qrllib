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
| SPHINCS+-256s robust | Hash-based | SPHINCS+ submission (pre-FIPS 205) — see SPHINCS+ notes | Stateless primitive; wallet path gated pending QRL's SLH-DSA parameter-set choice |
| XMSS | Hash-based | Pre-standardisation; see XMSS notes | QRL v1 → v2 migration |

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

Wallet-level `sign` / `verify_*` bind every signature to its descriptor via a fixed 8-byte domain-separated context: `"ZOND" || SIGNING_CONTEXT_VERSION || descriptor`. ML-DSA-87 passes it as the FIPS 204 ctx parameter; SPHINCS+-256s prepends it to the message. Callers do not need to construct the context themselves — wallet helpers do it internally — but `qrllib::signing_context(descriptor)` is exposed for parity with go-qrllib. Bumping `SIGNING_CONTEXT_VERSION` is a hard break of the signature wire format.

Common wallet construction/restoration methods:

| Type | Constructors |
|------|--------------|
| `MlDsa87Wallet` | `generate`, `from_seed`, `from_hex_seed`, `from_extended_seed`, `from_hex_extended_seed`, `from_mnemonic` |
| `SphincsPlus256sWallet` | `generate`, `from_seed`, `from_hex_seed`, `from_extended_seed`, `from_hex_extended_seed`, `from_mnemonic` |
| `LegacyXmssWallet` | `new`, `new_from_seed`, `new_from_extended_seed` |

Common wallet accessors:

| Type | Accessors |
|------|-----------|
| `MlDsa87Wallet` | `seed`, `extended_seed`, `hex_seed`, `mnemonic`, `descriptor`, `public_key`, `secret_key`, `address`, `address_string`, `sign` (hedged), `sign_deterministic`, `zeroize` |
| `SphincsPlus256sWallet` | `seed`, `extended_seed`, `hex_seed`, `mnemonic`, `descriptor`, `public_key`, `secret_key`, `address`, `address_string`, `sign`, `sign_attached`, `zeroize` |
| `LegacyXmssWallet` | `height`, `seed`, `extended_seed`, `hex_seed`, `mnemonic`, `root`, `public_key`, `secret_key`, `address`, `index`, `set_index`, `sign`, `descriptor`, `zeroize` |

Accessors that return secret material (`seed`, `secret_key`, `secret_key_bytes`) hand back `zeroize::Zeroizing<T>` values that clear on drop. They dereference transparently to the underlying byte array or `Vec<u8>`, so passing them to `hex::encode`, `Sha256::digest`, `.iter()`, or the verify helpers works unchanged. Explicit `.zeroize()` remains available, and every secret-bearing wallet and signer type now also implements `Drop` that zeroizes on scope exit — forgetting to call `.zeroize()` no longer leaves residual secrets in memory.

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
| `MlDsa87` | `generate`, `from_seed`, `from_hex_seed`, `public_key_bytes`, `secret_key_bytes`, `seed`, `hex_seed`, `sign` (hedged), `sign_deterministic`, `sign_attached`, `sign_attached_deterministic`, `verify`, `zeroize` |
| `SphincsPlus256s` | `generate`, `from_seed`, `from_hex_seed`, `public_key_bytes`, `secret_key_bytes`, `seed`, `hex_seed`, `sign`, `sign_attached`, `zeroize` |
| `Dilithium` | `generate`, `from_seed`, `from_hex_seed`, `public_key_bytes`, `secret_key_bytes`, `seed`, `hex_seed`, `sign` (hedged), `sign_deterministic`, `sign_attached`, `sign_attached_deterministic`, `verify`, `zeroize` |
| `Xmss` | `initialize_tree`, `seed`, `secret_key`, `public_seed`, `root`, `public_key`, `hash_function`, `height`, `index`, `set_index`, `sign`, `zeroize` |

Low-level verification and sealed-message helpers:

| API | Purpose |
|-----|---------|
| `mldsa::verify_bytes` | Verify ML-DSA-87 with explicit FIPS 204 context |
| `sign_mldsa_with_secret_key` | Stateless ML-DSA-87 secret-key signing with explicit FIPS 204 context (hedged by default per FIPS 204 §3.4 — TOB-QRLLIB-6) |
| `sign_mldsa_with_secret_key_deterministic` | FIPS 204 §3.5 deterministic-mode opt-in (use for RANDAO-style protocols and KAT vector reproduction) |
| `open`, `extract_message`, `extract_signature` | ML-DSA-87 attached-signature helpers |
| `verify_sphincsplus_signature` | Verify detached SPHINCS+ signatures |
| `sphincsplus_open`, `sphincsplus_extract_message`, `sphincsplus_extract_signature` | SPHINCS+ attached-signature helpers |
| `verify_dilithium_signature` | Verify detached legacy Dilithium signatures |
| `sign_dilithium_with_secret_key` | Stateless legacy Dilithium secret-key signing (hedged by default) |
| `sign_dilithium_with_secret_key_deterministic` | Deterministic-mode opt-in (KAT vector reproduction) |
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
| `signing_context`, `SIGNING_CONTEXT_VERSION`, `SIGNING_CONTEXT_PREFIX`, `SIGNING_CONTEXT_SIZE` | Domain-separated signing-context helpers used by wallet-level sign/verify |
| `QrllibError`, `Result` | Shared error and result types |

### Hedged vs Deterministic Signing

ML-DSA-87 and Dilithium are **hedged by default** per FIPS 204 §3.4 — the FIPS-recommended mode and the TOB-QRLLIB-6 default (TOB-6 audit recommendation applied here for parity with `go-qrllib`):

- **`sign` / `sign_attached`** (default) draw fresh `crypto/rand` randomness into the per-signature value on every call. Two signs of the same `(secret_key, [context,] message)` produce **distinct** signature bytes; both verify under the same public key. This frustrates fault-injection attacks against deterministic signing — an adversary who could differentiate two same-message signatures and recover `s1`/`s2` by lattice differential analysis no longer can. Verification is unchanged and existing verifiers are unaffected.
- **`sign_deterministic` / `sign_attached_deterministic`** (FIPS 204 §3.5 opt-in) use a fixed all-zero per-signature value, so two signs of the same input yield byte-identical signatures. **Use only when the deterministic property is itself a security or protocol requirement** — for example, RANDAO-style verifiable beacon contributions where each validator must produce the same signature for the same input, or ACVP / KAT / cross-verification test-vector reproduction.

SPHINCS+-256s robust is randomised-by-default per its parameter-set definition; no explicit deterministic counterpart is needed.

### Algorithm Selection Guide

| Requirement | Recommended |
|-------------|-------------|
| General-purpose stateless signing, best performance | `MlDsa87` (hedged by default) |
| QRL V2.0 wallet transactions | `MlDsa87Wallet` (descriptor-bound signing context) |
| Deterministic signatures (e.g. RANDAO-style beacon contributions) | `MlDsa87::sign_deterministic` (FIPS 204 §3.5 opt-in) |
| Maximum security, don't trust lattice assumptions | `SphincsPlus256s` raw primitive (wallet path gated, see SPHINCS+ notes) |
| Legacy QRL v1 address compatibility | `LegacyXmssWallet` (with extreme care; see XMSS notes) |

### Safe XMSS Usage

XMSS is a **stateful** scheme. Signing two different messages under the same OTS index causes irreversible compromise of the one-time WOTS chains at that position. The library takes a two-part approach:

1. The type system forbids cloning: `Xmss` and `LegacyXmssWallet` do not implement `Clone`. Accidental duplication (and the resulting immediate index reuse) is a compile error.
2. Everything else — index persistence, backup-and-restore reconciliation, single-writer discipline across processes or threads, and key rotation before tree exhaustion — is the **application's responsibility**. See [SECURITY.md](SECURITY.md) for the full threat model and operational checklist.

If you serialise the secret-key bytes via `wallet.secret_key()` and re-instantiate later, you must make absolutely sure the new instance starts at an OTS index greater than or equal to the highest used index. The library cannot enforce this across process or device boundaries.

### XMSS notes

This library's XMSS implementation **predates RFC 8391** (the spec was published in August 2018, after QRL v1 launched) and is retained as a v1 → v2 **migration vehicle** — it is not intended as a general standards-tracking XMSS implementation. Where parameter-set choices happen to overlap with RFC 8391 (XMSS-SHA2_10_256 and XMSS-SHAKE_256_10_256), signatures produced by `rust-qrllib` verify under the RFC 8391 reference implementation (see `.github/workflows/cross-verify.yml`). The library does **not** track later standards updates such as NIST SP 800-208 (October 2020), which refined `expand_seed` to take additional inputs — adopting that refinement would change the keypair derived from any given v1 seed and break compatibility with existing v1 mainnet addresses. **`Shake128`** is a pre-standardisation QRL-specific hash variant, retained for v1 mainnet address compatibility only, and is not part of RFC 8391 or SP 800-208. For new wallets, use **`MlDsa87Wallet`** (FIPS 204). See [SECURITY.md](SECURITY.md) for the full provenance discussion.

### SPHINCS+ notes

The implementation here is the **SPHINCS+ submission** (pre-FIPS 205), specifically `SHAKE-256s-robust`. NIST published [SLH-DSA (FIPS 205)](https://csrc.nist.gov/pubs/fips/205/final) in August 2024 as the standardised successor; FIPS 205 differs from the SPHINCS+ submission in parameter-set details. The QRL wallet layer **does not currently issue new SPHINCS+/SLH-DSA wallets** — `WalletType::SphincsPlus256s.is_issuable()` returns `false` until QRL settles on a specific SLH-DSA parameter set and the implementation is updated to match it. The wallet type is reserved in the descriptor format so existing addresses keep working (`is_verifiable()` always returns `true`). Direct use of the raw [`SphincsPlus256s`] primitive (outside the wallet layer) remains unrestricted with the caveat that the parameter set may change once SLH-DSA finalises for QRL. Developers who need to construct SPHINCS+ wallets locally can opt in via the `experimental-sphincsplus-issuance` Cargo feature (`cargo build --features experimental-sphincsplus-issuance`). For new wallets, use **`MlDsa87Wallet`**.

### Keeping Secrets in Memory for the Minimum Time

Every secret-bearing type (`Seed`, `ExtendedSeed`, `MlDsa87`, `Dilithium`, `SphincsPlus256s`, `Xmss`, `MlDsa87Wallet`, `SphincsPlus256sWallet`, `LegacyXmssWallet`) implements `Drop` that zeroizes the backing buffer. You do not need to call `.zeroize()` explicitly for the happy-path — the value clears when it goes out of scope. Explicit `.zeroize()` remains available for long-lived signers that want to wipe their state mid-lifetime.

Owned-secret accessors (`seed`, `secret_key`, `secret_key_bytes`) return `zeroize::Zeroizing<T>`, so caller-held copies also clear on drop.

If, after an explicit `.zeroize()`, you call `sign` or `seal` on a still-reachable signer, the library returns `QrllibError::MlDsaSecretKeyZeroized` / `DilithiumSecretKeyZeroized` / `SphincsPlusSecretKeyZeroized` / `XmssSecretKeyZeroized` rather than producing a bogus signature from the all-zero key.

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

### Handle-Based Wasm API (preferred)

The handle-based API accepts the extended seed (or parameters) **once**, stores the wallet inside wasm linear memory, and returns a `u32` handle. Subsequent sign / snapshot calls pass the handle — the seed hex string does not have to live on the JavaScript heap between operations. On `close_wallet(handle)` the wallet's `Drop` runs and zeroizes the stored secret state.

| Function | Purpose |
|----------|---------|
| `create_mldsa_wallet()` | Generate a fresh ML-DSA-87 wallet, return a handle |
| `open_mldsa_wallet(extendedSeedHex)` | Restore an ML-DSA-87 wallet from its extended seed, return a handle |
| `create_sphincsplus_wallet()` | Generate a fresh SPHINCS+-256s wallet, return a handle |
| `open_sphincsplus_wallet(extendedSeedHex)` | Restore a SPHINCS+-256s wallet, return a handle |
| `create_legacy_xmss_wallet(height, hashFunction)` | Generate a fresh legacy XMSS wallet, return a handle |
| `open_legacy_xmss_wallet(extendedSeedHex, index)` | Restore a legacy XMSS wallet at an explicit OTS index, return a handle |
| `create_dilithium_signer()` | Generate a fresh legacy Dilithium signer, return a handle |
| `open_dilithium_signer(seedHex)` | Restore a legacy Dilithium signer, return a handle |
| `wallet_snapshot(handle)` | Return the wallet's snapshot JSON |
| `wallet_sign(handle, message)` | Sign `message` with the wallet. Advances the OTS index for legacy-XMSS entries |
| `close_wallet(handle)` | Remove the registry entry; `Drop` zeroizes the stored secret |
| `close_all_wallets()` | Remove every registry entry — intended for page teardown |

Browser callers should prefer this API: the seed crosses the wasm/JS boundary exactly once at `open_*_wallet` time. The handle is a plain `u32`; JavaScript numbers represent it without precision loss.

### Legacy String-Based Wasm API

These entry points are retained for backwards compatibility. They re-decode the seed on every signing call and are superseded by the handle-based API above for new consumers.

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

Recommended — handle-based API (seed crosses the wasm/JS boundary only once):

```ts
import init, {
  create_mldsa_wallet,
  wallet_snapshot,
  wallet_sign,
  close_wallet,
  verify_message,
} from './pkg/qrllib_wasm'

await init()

const handle = create_mldsa_wallet()
try {
  const snapshot = wallet_snapshot(handle)
  const signed = wallet_sign(handle, 'The sleeper must awaken')
  const ok = verify_message(
    snapshot.publicKeyHex,
    snapshot.descriptorHex,
    'The sleeper must awaken',
    signed.signatureHex,
  )
  console.assert(ok)
} finally {
  close_wallet(handle) // zeroizes the in-wasm wallet state
}
```

Legacy string-per-call pattern (still works, retained for compatibility):

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

The Vue demo keeps a typed wrapper in `demo/src/qrllib.ts` that mirrors the wasm exports; as of audit revision 1.2 it continues to target the legacy string-based path, and migrating to the handle API is tracked as a follow-on task.

## Browser Demo

The demo builds the wasm package locally before Vite compiles the Vue app.

```bash
cd demo
npm ci
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

The library provides a narrow type-level guard: `Xmss` and `LegacyXmssWallet` do not implement `Clone`, so accidental duplication of a stateful signer is a compile error. Every other part of the contract is the application's responsibility:

- Never reuse an index.
- Persist the updated index before using or broadcasting a signature.
- Never sign concurrently from the same XMSS wallet.
- Never restore a wallet from backup without reconciling the highest used index.
- Rotate keys before the tree is exhausted.

For new applications, prefer ML-DSA-87 or SPHINCS+-256s robust. See [SECURITY.md](SECURITY.md) and the **Safe XMSS Usage** subsection in the Native Rust API for the full operational checklist.

## Verification

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo llvm-cov --locked --package qrllib --summary-only
cd demo && npm run build
```

Run coverage on nightly (`cargo +nightly llvm-cov --locked --package qrllib --summary-only`) to honour `#[cfg_attr(coverage_nightly, coverage(off))]` exclusions on defensive helpers whose guards cannot fire from internal callers (e.g. `constant_time_eq` length-mismatch, the duplicate length guards inside `crypto_sign_open*`). On stable the attribute is a no-op and those branches count against the ceiling.

Additional CI coverage:

- ML-DSA-87 is an in-repo Rust port of the `go-qrllib` implementation, not a wrapper around a packaged ML-DSA crate.
- ML-DSA-87 ACVP vectors are pulled from NIST ACVP-Server at workflow runtime.
- Dilithium, ML-DSA-87, SPHINCS+, and XMSS are cross-verified against external reference implementations.
- Rust and npm direct dependencies are exact-pinned, CI uses lockfile-enforced installs, and GitHub Actions are pinned by commit SHA.
- `cargo audit` and `cargo deny` enforce supply-chain checks.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, algorithm notes, release verification, SBOMs, and attestation details.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
