# @theqrl/qrllib-wasm

[![npm](https://img.shields.io/npm/v/@theqrl/qrllib-wasm.svg)](https://www.npmjs.com/package/@theqrl/qrllib-wasm)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/theQRL/rust-qrllib/blob/main/LICENSE)

WebAssembly bindings for [QRL](https://www.theqrl.org/) (Quantum Resistant
Ledger) post-quantum cryptography — ML-DSA-87 (FIPS 204), SPHINCS+-256s, and
XMSS wallets, plus QRL address/signature helpers. Compiled with `wasm-pack`
(`--target web`) from [`theQRL/rust-qrllib`](https://github.com/theQRL/rust-qrllib);
the version tracks the `qrllib` crate.

## Install

```bash
npm install @theqrl/qrllib-wasm
```

## Usage

This is a `--target web` build: the default export is an `init` function you must
call once before any other export. How `init` receives the `.wasm` differs by
environment.

### Node.js

Load the `.wasm` bytes and pass them to `init`:

```js
import init, { generate_wallet, sign_message, verify_message } from '@theqrl/qrllib-wasm';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgDir = dirname(fileURLToPath(import.meta.resolve('@theqrl/qrllib-wasm')));
await init({ module_or_path: await readFile(join(pkgDir, 'qrllib_wasm_bg.wasm')) });

const wallet = generate_wallet();            // { scheme, address, extendedSeedHex, publicKeyHex, descriptorHex, ... }
const signature = sign_message(wallet.extendedSeedHex, 'hello, post-quantum world');
const ok = verify_message(
  wallet.publicKeyHex,
  wallet.descriptorHex,
  'hello, post-quantum world',
  signature.signatureHex,
);
console.log(ok); // true
```

### Browser / bundler

With a bundler (Vite, webpack, Rollup) or a native `<script type="module">`, the
`.wasm` asset is resolved for you, so `init()` takes no argument:

```js
import init, { generate_wallet } from '@theqrl/qrllib-wasm';

await init();
const wallet = generate_wallet();
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
> [repository](https://github.com/theQRL/rust-qrllib) for details.

## License

[MIT](https://github.com/theQRL/rust-qrllib/blob/main/LICENSE)
