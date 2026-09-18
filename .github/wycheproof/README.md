# Wycheproof Test Vector Verification

This directory documents the CI integration of the
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) and
[C2SP/CCTV](https://github.com/C2SP/CCTV) test vectors (ML-DSA-87 and
ML-KEM-1024) into `rust-qrllib`. There is no tooling in this directory — the
test vectors are consumed directly from the upstream files at CI time. This
page exists so reviewers can see at a glance what is covered and how.

## How It Works

The GitHub Action (`.github/workflows/wycheproof.yml`) clones the upstream
repositories at their latest commit and runs `rust-qrllib` against the upstream
vectors. Vectors are never vendored — they always come directly from upstream.

Each test reads its vector directory from an environment variable
(`WYCHEPROOF_VECTORS_DIR`, `CCTV_VECTORS_DIR`); when the variable is unset the
test logs a skip and passes, so day-to-day `cargo test` stays fast and offline.

The workflow tracks upstream `master`. If a future legitimate-failure case
appears (e.g., upstream adds a vector class a verifier doesn't yet handle), pin
to a specific commit and bump deliberately.

## ML-DSA-87

The in-crate `mldsa::wycheproof` module (`crates/qrllib/src/mldsa/wycheproof.rs`)
walks `mldsa_87_verify_test.json`, calls `rust-qrllib`'s `verify_bytes` for each
test vector, and asserts the result matches the expected `result` field.

It is a lib test rather than an integration test because three `valid`
vectors are signed under weak keys: tcId 66 and 174 (flag `ZeroPublicKey`,
all-zero t1) and tcId 240 (flag `MissingReduction`, every t1 coefficient
1023). FIPS 204 Algorithm 8 has no key-validity step, so the primitive must
accept them, but the public `PublicKey::from_bytes` rejects both keys
(`QrllibError::WeakPublicKey`; the rustdoc for `validate_mldsa_public_key`
states the rule). The harness wraps each group's key with the
`#[cfg(test)]`-only `PublicKey::from_bytes_unchecked`, which downstream crates
cannot reach, asserts that exactly those groups' keys are rejected as weak and
every other well-formed key passes validation, and asserts that at least one
`valid` vector under each of the two weak keys was accepted. If that last
assertion ever fails, key validation has leaked into the primitive.

| Vector file | Source | Description |
|-------------|--------|-------------|
| `mldsa_87_verify_test.json` | upstream `testvectors_v1/` | ML-DSA-87 verification edge cases: malleability, truncated/extended signatures, wrong-length public keys, weak `ZeroPublicKey` (all-zero t1) and `MissingReduction` (all-1023 t1) keys, context-string variants, and similar boundary conditions. |

## ML-KEM-1024

`crates/qrllib/tests/wycheproof_mlkem.rs` is verified against two upstreams,
both consumed directly at CI time by the `mlkem1024-wycheproof` job. Unlike the
go-qrllib harness (which is in-package to reach a test-only entry point), the
Rust harness is an ordinary integration test: derandomised encapsulation is
exercised through the public [`EncapsulationKey::encapsulate_deterministic`].

1. **C2SP/wycheproof** `testvectors_v1/mlkem_1024_*.json` (via
   `WYCHEPROOF_VECTORS_DIR`):

   | Vector file | What it exercises |
   |-------------|-------------------|
   | `mlkem_1024_keygen_seed_test.json` | seed (`d‖z`) → encapsulation-key derivation (100 vectors) |
   | `mlkem_1024_encaps_test.json` | derandomised encapsulation (`ek`,`m` → `c`,`K`) and encapsulation-key validation, incl. `ModulusOverflow` rejections (~270 vectors) |
   | `mlkem_1024_test.json` | decapsulation (`seed`,`c` → `K`), incl. implicit-rejection and `Strcmp` constant-time-comparison edge cases, plus structural rejections (~190 vectors) |

   `mlkem_1024_semi_expanded_decaps_test.json` is **not** consumed — it uses the
   3168-byte expanded decapsulation-key format, while `rust-qrllib`'s public API
   loads the 64-byte seed form. (The expanded form *is* exercised by the ACVP
   tests, which read it from the NIST vectors.)

2. **C2SP/CCTV** `ML-KEM/modulus/ML-KEM-1024.txt.gz` (via `CCTV_VECTORS_DIR`):
   1040 invalid encapsulation keys, each with one coefficient forced into
   `[q, 2¹²-1]` at every position — all must be rejected by the `byte_decode12`
   modulus check. This is the exhaustive counterpart to wycheproof's
   `ModulusOverflow` cases. The workflow decompresses the upstream `.txt.gz` to
   `.txt` so the Rust test needs no gzip dependency.

NIST ACVP functional vectors (KeyGen / Encaps / Decaps / key-checks) run
separately in `.github/workflows/acvp.yml` (see `.github/acvp/README.md`), so
they are not duplicated here.

## Result-Field Semantics

Wycheproof's `result` field is `valid` or `invalid` for the ML-KEM vectors used
here (ML-DSA additionally uses `acceptable`):

| Value | Expectation |
|-------|-------------|
| `valid` | The operation must succeed and (for KAT vectors) produce the expected bytes. |
| `invalid` | The operation must be rejected at the API boundary, or — for decapsulation implicit-rejection cases flagged `valid` — yield the pseudo-random rejection key rather than an error. |
| `acceptable` | (ML-DSA only) Either outcome is permitted by the spec; the observed outcome is logged but not failed. |

## Running Locally

```bash
# ML-DSA-87
git clone --depth 1 https://github.com/C2SP/wycheproof.git /tmp/wycheproof
WYCHEPROOF_VECTORS_DIR=/tmp/wycheproof/testvectors_v1 \
  cargo test --package qrllib --lib 'mldsa::wycheproof::' -- --nocapture

# ML-KEM-1024 (+ CCTV modulus corpus)
git clone --depth 1 https://github.com/C2SP/CCTV.git /tmp/cctv
gunzip -kf /tmp/cctv/ML-KEM/modulus/ML-KEM-1024.txt.gz
WYCHEPROOF_VECTORS_DIR=/tmp/wycheproof/testvectors_v1 \
  CCTV_VECTORS_DIR=/tmp/cctv/ML-KEM \
  cargo test --package qrllib --test wycheproof_mlkem -- --nocapture
```

## Skip Behaviour

The Wycheproof and CCTV tests are gated behind environment-variable presence
rather than a build tag: with the variables unset they print a skip notice and
pass, so normal `cargo test` does not require the (large) upstream vector repos
to be present.
