# Cross-Implementation Verification

This directory contains helper files for cross-implementation verification tests run by GitHub Actions.

## Overview

These tests verify that `rust-qrllib`'s signature implementations are interoperable with the authoritative reference implementations.

## Tests

### ML-DSA-87 (FIPS 204)
- Reference: https://github.com/pq-crystals/dilithium (current master)
- Tests bidirectional signature verification with context parameter
- Key sizes: PK=2592, SK=4896, Sig=4627 bytes

### SPHINCS+ (SHAKE-256s-robust)
- Reference: https://github.com/sphincs/sphincsplus @ branch `consistent-basew`
- Parameters: PARAMS=sphincs-shake-256s THASH=robust
- Tests bidirectional signature verification
- Key sizes: PK=64, SK=128, Seed=96, Sig=29792 bytes
- Note: Uses `consistent-basew` branch which has the corrected FORS index decoding (see [NIST PQC Forum discussion](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/88tuvtb7nN4/m/DA1QCoJWBAAJ))

### XMSS (SHA2_10_256) - Bidirectional via the `rfc8391` module
- Reference: https://github.com/XMSS/xmss-reference @ commit `7793c40`
- Parameters: XMSS-SHA2_10_256 (OID 0x00000001), height=10, n=32, w=16
- Tests **bidirectional** verification using
  [`crates/qrllib/src/xmss/rfc8391.rs`](../../crates/qrllib/src/xmss/rfc8391.rs)
  on the `rust-qrllib` side
- Key sizes: PK=64 (`root || pub_seed`) or 68 (RFC layout with OID),
  SK=132, Seed=48 (QRL convention) or 96 (expanded-seed convention),
  Sig=2500 bytes

#### Historical and reference-pin rationale

QRL deployed XMSS before RFC 8391 was published in May 2018. The
eventual RFC specified a closely aligned construction for the overlapping
SHA2-256 and SHAKE256 parameter families, including the signature byte layout.
Its optional pseudorandom private-key-generation example uses the same
`PRF(seed, toByte(i, 32))` form retained by QRL.

Commit `7793c40` (2020-04-14) is the last reference revision using that
compatible derivation. Commit
[`3e28db2`](https://github.com/XMSS/xmss-reference/commit/3e28db2)
later introduced `PRFkeygen(SK_SEED, PUB_SEED || ADRS)`, the construction
selected for NIST SP 800-208's stricter profile. Changing QRL's deployed
derivation would change tree roots and immutable QRL v1 addresses, so this pin
deliberately tests the construction QRL must preserve. See
[SECURITY.md](../../SECURITY.md) "XMSS provenance and standards alignment" for
the complete scope statement.

#### Why an interop module is needed

The primary `Xmss::initialize_tree` entry point and the reference differ in two
external conventions even though their overlapping signature construction is
compatible:

1. **Seed expansion**: QRL SHAKE256-expands a 48-byte wallet seed into the
   96 bytes `SK_SEED || SK_PRF || PUB_SEED`. The reference consumes those
   96 bytes directly; RFC 8391 does not prescribe QRL's outer wallet-seed
   convention.
2. **Public-key prefix**: QRL prefixes `root || pub_seed` with a three-byte
   descriptor. RFC 8391 public keys use a four-byte parameter-set OID.

The `xmss::rfc8391` module bridges both conventions. Its direct 96-byte
entry point reproduces the reference keypair, while its marshal/unmarshal
helpers convert public-key encodings. Signature bytes require no conversion.

#### What the two directions prove

- **Rust → reference**: `xmss_sign.rs` creates a QRL key and signature;
  `xmss_verify_ref.c` supplies the RFC OID and verifies the signature using the
  reference implementation.
- **Reference → Rust**: `xmss_sign_ref.c` injects a fixed 96-byte expanded seed
  through the pinned reference's `randombytes()` interface, signs, and writes
  the artefacts. `xmss_verify_reverse.rs` reconstructs the same key through the
  `rfc8391` module, asserts that `root || pub_seed` matches byte-for-byte, and
  verifies the signature.

The workflow proves `XMSS-SHA2_10_256`. The interop module maps all six RFC
8391 `n=32` SHA2/SHAKE parameter OIDs at heights 10, 16, and 20, but this
workflow does not claim independent reference coverage for all six.

**Note**: XMSS is retained for immutable QRL v1 address compatibility and v1 →
v2 migration. For new wallets, use ML-DSA-87 (FIPS 204).

## Files

| File | Description |
|------|-------------|
| `../../crates/qrllib/examples/mldsa87_sign.rs` | Generate `rust-qrllib` ML-DSA-87 signature |
| `../../crates/qrllib/examples/mldsa87_verify.rs` | Verify reference ML-DSA-87 signature with `rust-qrllib` |
| `mldsa87_sign_ref.c` | Generate pq-crystals ML-DSA-87 signature |
| `mldsa87_verify_ref.c` | Verify `rust-qrllib` ML-DSA-87 signature with pq-crystals |
| `../../crates/qrllib/examples/sphincs_sign.rs` | Generate `rust-qrllib` SPHINCS+ signature |
| `../../crates/qrllib/examples/sphincs_verify.rs` | Verify reference SPHINCS+ signature with `rust-qrllib` |
| `sphincs_sign_ref.c` | Generate reference SPHINCS+ signature |
| `sphincs_verify_ref.c` | Verify `rust-qrllib` SPHINCS+ signature with reference |
| `../../crates/qrllib/examples/xmss_sign.rs` | Generate `rust-qrllib` XMSS signature |
| `xmss_verify_ref.c` | Verify `rust-qrllib` XMSS signature with reference (forward direction) |
| `xmss_sign_ref.c` | Generate reference XMSS signature from a fixed expanded seed (reverse direction) |
| `../../crates/qrllib/examples/xmss_verify_reverse.rs` | Reconstruct the reference key and verify its signature (reverse direction) |

## Running Locally

```bash
# ML-DSA-87
git clone https://github.com/pq-crystals/dilithium.git /tmp/mldsa-ref
cd /path/to/rust-qrllib
cargo run -p qrllib --example mldsa87_sign
cd /tmp/mldsa-ref/ref
gcc -DDILITHIUM_MODE=5 -I. -O2 -o /tmp/verify \
    /path/to/rust-qrllib/.github/cross-verify/mldsa87_verify_ref.c \
    sign.c packing.c polyvec.c poly.c ntt.c reduce.c \
    rounding.c symmetric-shake.c fips202.c randombytes.c
/tmp/verify

# SPHINCS+ (SHAKE-256s-robust)
git clone --branch consistent-basew https://github.com/sphincs/sphincsplus.git /tmp/sphincs-ref
cd /path/to/rust-qrllib
cargo run -p qrllib --example sphincs_sign
cd /tmp/sphincs-ref/ref
gcc -DPARAMS=sphincs-shake-256s -DTHASH=robust -I. -O2 -o /tmp/verify \
    /path/to/rust-qrllib/.github/cross-verify/sphincs_verify_ref.c \
    address.c merkle.c wots.c wotsx1.c utils.c utilsx1.c \
    fors.c sign.c hash_shake.c thash_shake_robust.c fips202.c randombytes.c
/tmp/verify

# XMSS (SHA2_10_256) - bidirectional, pinned to the compatible derivation
git clone https://github.com/XMSS/xmss-reference.git /tmp/xmss-ref
cd /tmp/xmss-ref && git checkout 7793c40

# Forward direction: rust-qrllib signs, reference verifies.
cd /path/to/rust-qrllib
cargo run --locked -p qrllib --example xmss_sign
cd /tmp/xmss-ref
gcc -Wall -O2 -I. -o /tmp/verify \
    /path/to/rust-qrllib/.github/cross-verify/xmss_verify_ref.c \
    params.c hash.c fips202.c hash_address.c randombytes.c wots.c \
    xmss.c xmss_core.c xmss_commons.c utils.c -lcrypto
/tmp/verify

# Reverse direction: the reference signs from a fixed expanded seed and
# rust-qrllib verifies. randombytes.c is intentionally omitted because
# xmss_sign_ref.c provides the deterministic randombytes() implementation.
cd /tmp/xmss-ref
gcc -Wall -O2 -I. -o /tmp/sign_ref \
    /path/to/rust-qrllib/.github/cross-verify/xmss_sign_ref.c \
    params.c hash.c fips202.c hash_address.c wots.c \
    xmss.c xmss_core.c xmss_commons.c utils.c -lcrypto
/tmp/sign_ref
cd /path/to/rust-qrllib
cargo run --locked -p qrllib --example xmss_verify_reverse
```
