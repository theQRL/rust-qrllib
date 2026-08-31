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
import init, {
  close_wallet,
  create_mldsa_wallet,
  wallet_sign,
  wallet_snapshot,
} from '@theqrl/qrllib-wasm';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgDir = dirname(fileURLToPath(import.meta.resolve('@theqrl/qrllib-wasm')));
await init({ module_or_path: await readFile(join(pkgDir, 'qrllib_wasm_bg.wasm')) });

const handle = create_mldsa_wallet();
try {
  const wallet = wallet_snapshot(handle);
  const signature = wallet_sign(handle, 'hello, post-quantum world');
  console.log(wallet.address, signature.verified);
} finally {
  close_wallet(handle);
}
```

### Browser / bundler

With a bundler (Vite, webpack, Rollup) or a native `<script type="module">`, the
`.wasm` asset is resolved for you, so `init()` takes no argument:

```js
import init, { close_wallet, create_mldsa_wallet, wallet_snapshot } from '@theqrl/qrllib-wasm';

await init();
const handle = create_mldsa_wallet();
try {
  console.log(wallet_snapshot(handle).address);
} finally {
  close_wallet(handle);
}
```

## API

Snapshot-style helpers (return a plain object): `generate_wallet`,
`wallet_from_extended_seed_hex`, `sign_message`, `verify_message`, the
`*_sphincsplus_*` and `*_xmss_*` equivalents. These legacy helpers pass an
extended seed through the JavaScript heap on each signing call and are retained
for compatibility.

Handle-based helpers (return a numeric wallet handle): `create_mldsa_wallet` /
`open_mldsa_wallet`, the SPHINCS+ and legacy-XMSS equivalents, then
`wallet_snapshot`, `wallet_sign`, `close_wallet`, `close_all_wallets`. New code
should prefer these helpers so a restored seed crosses the JS/WASM boundary only
once. Always close handles when they are no longer needed.

> **SPHINCS+ note:** the SPHINCS+ wallet path is disabled by default
> (pre-FIPS-205 parameter set, TOB-QRLLIB-4). Wallet creation returns
> `WalletTypeNotIssuable` and `verify_sphincsplus_message` returns `false`
> unless the crate is built with `experimental-sphincsplus-issuance`. This
> matches go-qrllib, where SPHINCSPLUS_256S is neither a valid nor a
> verifiable production wallet type. See the
> [repository](https://github.com/theQRL/rust-qrllib) for details.

## Security

- WASM linear memory is ordinary process memory, not an HSM or secure enclave.
- Closing a handle removes the wallet and runs Rust zeroization, but JavaScript
  strings and engine-created copies cannot be reliably wiped.
- The handle registry is local to one WASM instance; handles are not durable
  wallet identifiers and must not be persisted.
- XMSS remains stateful. Persist `xmssNextIndex` before using a signature and
  prevent multiple tabs, workers, processes, or restored copies from signing
  with the same key.

See the repository [security policy](https://github.com/theQRL/rust-qrllib/blob/main/SECURITY.md)
for the full threat model.

## License

[MIT](https://github.com/theQRL/rust-qrllib/blob/main/LICENSE)
