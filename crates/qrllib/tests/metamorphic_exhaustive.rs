//! Exhaustive bit-by-bit metamorphic tests for ML-DSA-87.
//!
//! Port of the ToB-handoff `metamorphic_test.go` (originally guarded
//! behind Go's `metamorphic` build tag). These tests iterate over
//! every bit of a public key, signature, or attached-sealed-signature
//! and assert verify/open rejects the single-bit-mauled variant; plus
//! a deterministic-signing diff property and a secret-key feature
//! scan.
//!
//! Slow (~20-60s in aggregate). Gated by the `METAMORPHIC_EXHAUSTIVE=1`
//! env var so day-to-day `cargo test` doesn't pay the cost — same
//! pattern the existing `acvp_mldsa.rs` and `wycheproof_mldsa.rs`
//! integration tests use. CI runs them via a dedicated step (see
//! `.github/workflows/test.yml`).
//!
//! API adaptations for the Rust port (post TOB-QRLLIB-6 / -12):
//!  - byte-equality assertions go through `sign_deterministic` /
//!    `sign_attached_deterministic` (default `sign` is hedged)
//!  - `Seal` → `sign_attached` rename applied
//!  - `Open` returns `Result<Option<Vec<u8>>>`

use std::env;

use qrllib::{
    ML_DSA_87_CRYPTO_SEED_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE,
    ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    mldsa::{sign_with_secret_key_deterministic, verify_bytes},
    open,
};

fn exhaustive_enabled() -> bool {
    matches!(env::var("METAMORPHIC_EXHAUSTIVE").as_deref(), Ok("1"))
}

struct Vector {
    name: &'static str,
    seed: [u8; ML_DSA_87_CRYPTO_SEED_SIZE],
    ctx: Vec<u8>,
    message: Vec<u8>,
}

fn corpus() -> Vec<Vector> {
    let zero = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    let mut ascending = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    for (i, b) in ascending.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut msg32 = [0_u8; 32];
    for (i, b) in msg32.iter_mut().enumerate() {
        *b = i as u8;
    }

    vec![
        Vector {
            name: "zero-seed-empty-ctx",
            seed: zero,
            ctx: Vec::new(),
            message: msg32.to_vec(),
        },
        Vector {
            name: "ascending-seed-max-ctx",
            seed: ascending,
            ctx: vec![0x42; 255],
            message: msg32.to_vec(),
        },
    ]
}

fn flip_single_bit(src: &[u8], bit: usize) -> Vec<u8> {
    let mut out = src.to_vec();
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

#[test]
fn metamorphic_verify_rejects_bit_mauled_public_keys() {
    if !exhaustive_enabled() {
        eprintln!("METAMORPHIC_EXHAUSTIVE not set; skipping");
        return;
    }
    for vec in corpus() {
        let signer = MlDsa87::from_seed(vec.seed);
        let signature = signer.sign(&vec.ctx, &vec.message).expect("sign");
        let pk = signer.public_key_bytes();
        assert!(verify_bytes(&vec.ctx, &vec.message, &signature, &pk).expect("baseline"));

        for bit in 0..(ML_DSA_87_PUBLIC_KEY_SIZE * 8) {
            let mauled = flip_single_bit(&pk, bit);
            let mut mauled_pk = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
            mauled_pk.copy_from_slice(&mauled);
            assert!(
                !verify_bytes(&vec.ctx, &vec.message, &signature, &mauled_pk).unwrap_or(false),
                "{}: bit-mauled pk verified at bit {}",
                vec.name,
                bit
            );
        }
    }
}

#[test]
fn metamorphic_verify_rejects_bit_mauled_messages() {
    if !exhaustive_enabled() {
        eprintln!("METAMORPHIC_EXHAUSTIVE not set; skipping");
        return;
    }
    for vec in corpus() {
        let signer = MlDsa87::from_seed(vec.seed);
        let signature = signer.sign(&vec.ctx, &vec.message).expect("sign");
        let pk = signer.public_key_bytes();
        assert!(verify_bytes(&vec.ctx, &vec.message, &signature, &pk).expect("baseline"));

        for bit in 0..(vec.message.len() * 8) {
            let mauled_msg = flip_single_bit(&vec.message, bit);
            assert!(
                !verify_bytes(&vec.ctx, &mauled_msg, &signature, &pk).expect("verify mauled"),
                "{}: bit-mauled message verified at bit {}",
                vec.name,
                bit
            );
        }
    }
}

#[test]
fn metamorphic_verify_rejects_bit_mauled_signatures() {
    if !exhaustive_enabled() {
        eprintln!("METAMORPHIC_EXHAUSTIVE not set; skipping");
        return;
    }
    for vec in corpus() {
        let signer = MlDsa87::from_seed(vec.seed);
        let signature = signer.sign(&vec.ctx, &vec.message).expect("sign");
        let pk = signer.public_key_bytes();
        assert!(verify_bytes(&vec.ctx, &vec.message, &signature, &pk).expect("baseline"));

        for bit in 0..(ML_DSA_87_SIGNATURE_SIZE * 8) {
            let mauled = flip_single_bit(&signature, bit);
            let mut mauled_sig = [0_u8; ML_DSA_87_SIGNATURE_SIZE];
            mauled_sig.copy_from_slice(&mauled);
            assert!(
                !verify_bytes(&vec.ctx, &vec.message, &mauled_sig, &pk).expect("verify"),
                "{}: bit-mauled sig verified at bit {}",
                vec.name,
                bit
            );
        }
    }
}

/// Asserts the metamorphic property "different msg → different signature
/// bytes" exhaustively. Routes through `sign_deterministic` so the
/// byte-equality assertion is meaningful under hedged-by-default
/// signing (TOB-QRLLIB-6).
#[test]
fn metamorphic_deterministic_signing_changes_on_bit_mauled_messages() {
    if !exhaustive_enabled() {
        eprintln!("METAMORPHIC_EXHAUSTIVE not set; skipping");
        return;
    }
    for vec in corpus() {
        let signer = MlDsa87::from_seed(vec.seed);
        let base = signer.sign_deterministic(&vec.ctx, &vec.message).expect("base");

        for bit in 0..(vec.message.len() * 8) {
            let mauled = flip_single_bit(&vec.message, bit);
            let mauled_sig = signer.sign_deterministic(&vec.ctx, &mauled).expect("sign");
            assert_ne!(
                mauled_sig, base,
                "{}: deterministic signing collision after single-bit message maul at bit {}",
                vec.name, bit
            );
        }
    }
}

/// Bit-flip each byte in three named regions of the secret key (rho /
/// key / tr) and record (a) how many bit flips still produce a
/// signature that verifies under the original public key, and (b) how
/// many preserve the exact baseline signature bytes. Routes through
/// deterministic signing so the byte-equality counter is meaningful.
///
/// Asserts at least one key-region flip preserves verification under
/// the original pk — a structural-redundancy signal for the deployed
/// SK layout.
#[test]
fn metamorphic_secret_key_mauling_feature_scan() {
    if !exhaustive_enabled() {
        eprintln!("METAMORPHIC_EXHAUSTIVE not set; skipping");
        return;
    }
    const SEED_BYTES: usize = ML_DSA_87_CRYPTO_SEED_SIZE; // 32
    const TR_BYTES: usize = 64;

    for vec in corpus() {
        let signer = MlDsa87::from_seed(vec.seed);
        let pk = signer.public_key_bytes();
        let sk_owned = signer.secret_key_bytes();
        let sk: &[u8; ML_DSA_87_SECRET_KEY_SIZE] = &sk_owned;
        let base = sign_with_secret_key_deterministic(&vec.ctx, &vec.message, sk).expect("base");

        let regions = [
            ("rho", 0_usize, SEED_BYTES),
            ("key", SEED_BYTES, 2 * SEED_BYTES),
            ("tr", 2 * SEED_BYTES, 2 * SEED_BYTES + TR_BYTES),
        ];

        for (name, start, end) in regions {
            let mut valid_count = 0_usize;
            let mut same_sig_count = 0_usize;
            let total_bits = (end - start) * 8;

            for rel_bit in 0..total_bits {
                let abs_bit = start * 8 + rel_bit;
                let mauled = flip_single_bit(sk, abs_bit);
                let mut mauled_sk = [0_u8; ML_DSA_87_SECRET_KEY_SIZE];
                mauled_sk.copy_from_slice(&mauled);

                let sig = sign_with_secret_key_deterministic(&vec.ctx, &vec.message, &mauled_sk)
                    .expect("sign mauled sk");

                if sig == base {
                    same_sig_count += 1;
                }
                if verify_bytes(&vec.ctx, &vec.message, &sig, &pk).unwrap_or(false) {
                    valid_count += 1;
                }
            }

            eprintln!(
                "{}: {}: {}/{} bit flips still produced signatures valid under the original public key; {}/{} preserved the exact original signature",
                vec.name, name, valid_count, total_bits, same_sig_count, total_bits
            );

            if name == "key" && valid_count == 0 {
                panic!("expected at least one key-region bit flip to preserve signing validity");
            }
        }
    }
}

/// Exhaustive bit-by-bit maul of the **attached-signature prefix**
/// portion of a sealed message; asserts Open rejects every single-bit
/// alteration. Mauls only the signature, not the message suffix
/// (matches the Go-side test's contract).
#[test]
fn metamorphic_sign_attached_open_rejects_bit_mauled_attached_signatures() {
    if !exhaustive_enabled() {
        eprintln!("METAMORPHIC_EXHAUSTIVE not set; skipping");
        return;
    }
    for vec in corpus() {
        let signer = MlDsa87::from_seed(vec.seed);
        let sealed = signer.sign_attached(&vec.ctx, &vec.message).expect("sign_attached");
        let pk = signer.public_key_bytes();

        let opened = open(&vec.ctx, &sealed, &pk).expect("baseline").expect("baseline msg");
        assert_eq!(opened, vec.message, "{}: baseline sealed message did not round-trip", vec.name);

        for bit in 0..(ML_DSA_87_SIGNATURE_SIZE * 8) {
            let mauled = flip_single_bit(&sealed[..ML_DSA_87_SIGNATURE_SIZE], bit);
            let mut mauled_sealed = mauled.clone();
            mauled_sealed.extend_from_slice(&sealed[ML_DSA_87_SIGNATURE_SIZE..]);

            assert!(
                open(&vec.ctx, &mauled_sealed, &pk).expect("open mauled").is_none(),
                "{}: bit-mauled attached signature opened successfully at bit {}",
                vec.name,
                bit
            );
        }
    }
}
