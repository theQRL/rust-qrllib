# @theqrl/qrllib-wasm

[![npm](https://img.shields.io/npm/v/@theqrl/qrllib-wasm.svg)](https://www.npmjs.com/package/@theqrl/qrllib-wasm)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/theqrl/rust-qrllib/blob/main/LICENSE)

WebAssembly bindings for [QRL](https://www.theqrl.org/) (Quantum Resistant
Ledger) post-quantum cryptography — ML-DSA-87 (FIPS 204), SPHINCS+-256s, and
XMSS wallets, plus QRL address/signature helpers. Compiled with `wasm-pack`
(`--target web`) from [`theqrl/rust-qrllib`](https://github.com/theqrl/rust-qrllib);
the version tracks the `qrllib` crate.

## Install

```bash
npm install @theqrl/qrllib-wasm
```

## Usage

This is a `--target web` build, so initialise the module once before calling any
export:

```js
import init, { generate_wallet, sign_message, verify_message } from '@theqrl/qrllib-wasm';

await init();

const wallet = generate_wallet();            // { scheme, address, extendedSeedHex, publicKeyHex, descriptorHex, ... }
const signature = sign_message(wallet.extendedSeedHex, 'hello, post-quantum world');
const ok = verify_message(
  wallet.publicKeyHex,
  wallet.descriptorHex,
  'hello, post-quantum world',
  signature.signatureHex,
);
```

## API

Snapshot-style helpers (return a plain object): `generate_wallet`,
`wallet_from_extended_seed_hex`, `sign_message`, `verify_message`, the
`*_sphincsplus_*` and `*_xmss_*` equivalents.

Handle-based helpers (return a numeric wallet handle): `create_mldsa_wallet` /
`open_mldsa_wallet`, the SPHINCS+ and legacy-XMSS equivalents, then
`wallet_snapshot`, `wallet_sign`, `close_wallet`, `close_all_wallets`.

> **SPHINCS+ note:** creating *new* SPHINCS+ wallets is disabled by default
> (pre-FIPS-205 parameter set, TOB-QRLLIB-4); verifying existing SPHINCS+
> signatures is always available. See the
> [repository](https://github.com/theqrl/rust-qrllib) for details.

## License

[MIT](https://github.com/theqrl/rust-qrllib/blob/main/LICENSE)
