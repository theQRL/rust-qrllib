//! Structured and metamorphic property tests for ML-DSA-87.
//!
//! Port of the ToB-handoff fuzz tests delivered during the
//! `go-qrllib` Trail of Bits engagement
//! (`crypto/ml_dsa_87/metamorphic_fuzz_test.go` and
//! `structured_fuzz_test.go`). Adapted to deterministic seeded loops
//! so they run on stable Rust under plain `cargo test` rather than
//! requiring `cargo-fuzz` (which is nightly-only). The Go-side
//! exhaustive bit-by-bit counterparts (originally guarded behind the
//! `metamorphic` build tag) live in `metamorphic_exhaustive.rs`
//! gated by the `METAMORPHIC_EXHAUSTIVE=1` env var.
//!
//! API adaptations for the Rust port (post TOB-QRLLIB-6 / -12):
//!  - `sign` is hedged by default; tests that depend on byte-equality
//!    of two signs over the same message use `sign_deterministic`
//!  - `Seal` → `sign_attached` rename applied throughout
//!  - `Open` already returned `Result<Option<Vec<u8>>>` in Rust

use qrllib::{
    ML_DSA_87_CRYPTO_SEED_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    QrllibError, mldsa::verify_bytes, open,
};

/// Hand-curated seed corpus mirroring the Go-side `f.Add(...)` entries:
/// covers all-zero, all-`0xFF`, and short / arbitrary seeds.
fn corpus_seeds() -> Vec<[u8; ML_DSA_87_CRYPTO_SEED_SIZE]> {
    let mut zero = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    let mut ones = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    for b in ones.iter_mut() {
        *b = 0xff;
    }
    let mut ascending = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    for (i, b) in ascending.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut seed_ascii = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    seed_ascii[..4].copy_from_slice(b"seed");
    let _ = &mut zero;
    vec![zero, ones, ascending, seed_ascii]
}

/// Hand-curated `(ctx, message, mutation_indices)` corpus mirroring
/// the Go-side fuzz seeds.
type CorpusInput = (Vec<u8>, Vec<u8>, (u32, u8));

fn corpus_inputs() -> Vec<CorpusInput> {
    vec![
        (b"ctx".to_vec(), b"message".to_vec(), (0, 0x01)),
        (vec![0x41_u8; 255], Vec::new(), (17, 0x80)),
        (vec![0x42_u8; 32], b"medium".repeat(8), (3, 0x07)),
    ]
}

fn flip_single_bit(src: &[u8], bit_index: u32) -> Vec<u8> {
    if src.is_empty() {
        return vec![1];
    }
    let mut out = src.to_vec();
    let bit = (bit_index as usize) % (out.len() * 8);
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

fn mutate_slice(base: &[u8], mutation: (u32, u8)) -> Vec<u8> {
    let (idx, mask) = mutation;
    if base.is_empty() {
        return vec![if mask == 0 { 0x01 } else { mask }];
    }
    let mut out = base.to_vec();
    let i = (idx as usize) % out.len();
    let m = if mask == 0 { 0x01 } else { mask };
    out[i] ^= m;
    out
}

fn mutate_array<const N: usize>(base: &[u8; N], mutation: (u32, u8)) -> [u8; N] {
    let (idx, mask) = mutation;
    let mut out = *base;
    let i = (idx as usize) % out.len();
    let m = if mask == 0 { 0x01 } else { mask };
    out[i] ^= m;
    out
}

// ============================================================
// Structured property tests (port of structured_fuzz_test.go)
// ============================================================

/// Port of `FuzzMLDSA87SignVerifyRoundTripMutate`: round-trip sign /
/// verify, then mutate each of ctx / msg / sig / pk and assert verify
/// fails.
#[test]
fn mldsa87_sign_verify_round_trip_mutate() {
    for seed in corpus_seeds() {
        for (ctx, message, mutation) in corpus_inputs() {
            let signer = MlDsa87::from_seed(seed);
            let signature = signer
                .sign(&ctx, &message)
                .unwrap_or_else(|e| panic!("sign with ctx_len={}: {:?}", ctx.len(), e));
            let pk = signer.public_key_bytes();

            assert!(
                verify_bytes(&ctx, &message, &signature, &pk).expect("verify"),
                "baseline signature failed verification (ctx_len={})",
                ctx.len()
            );

            // Mutated context → reject.
            let mutated_ctx = mutate_slice(&ctx, mutation);
            if mutated_ctx != ctx && mutated_ctx.len() <= 255 {
                assert!(
                    !verify_bytes(&mutated_ctx, &message, &signature, &pk).unwrap_or(false),
                    "verify accepted mutated ctx"
                );
            }

            // Mutated message → reject.
            let mutated_msg = mutate_slice(&message, mutation);
            assert_ne!(mutated_msg, message, "message mutation did not change input");
            assert!(
                !verify_bytes(&ctx, &mutated_msg, &signature, &pk).expect("verify mutated msg"),
                "verify accepted mutated message"
            );

            // Mutated signature → reject.
            let mutated_sig = mutate_array(&signature, mutation);
            assert!(
                !verify_bytes(&ctx, &message, &mutated_sig, &pk).expect("verify mutated sig"),
                "verify accepted mutated signature"
            );

            // Mutated public key → reject.
            let mutated_pk = mutate_array(&pk, mutation);
            assert!(
                !verify_bytes(&ctx, &message, &signature, &mutated_pk).expect("verify mutated pk"),
                "verify accepted mutated public key"
            );
        }
    }
}

/// Port of `FuzzMLDSA87SignAttachedOpenRoundTripMutate`: sign_attached
/// then Open round-trip, plus rejection of mutated ctx / sealed / pk.
#[test]
fn mldsa87_sign_attached_open_round_trip_mutate() {
    for seed in corpus_seeds() {
        for (ctx, message, mutation) in corpus_inputs() {
            let signer = MlDsa87::from_seed(seed);
            let sealed = signer.sign_attached(&ctx, &message).expect("sign_attached");
            let pk = signer.public_key_bytes();

            let opened =
                open(&ctx, &sealed, &pk).expect("open").expect("open did not recover message");
            assert_eq!(opened, message, "Open did not recover the original message");

            // Mutated context → Open fails.
            let mutated_ctx = mutate_slice(&ctx, mutation);
            if mutated_ctx != ctx && mutated_ctx.len() <= 255 {
                assert!(
                    open(&mutated_ctx, &sealed, &pk).unwrap_or(None).is_none(),
                    "Open succeeded with mutated context"
                );
            }

            // Mutated sealed message → Open fails.
            let mutated_sealed = mutate_slice(&sealed, mutation);
            assert!(
                open(&ctx, &mutated_sealed, &pk).expect("open").is_none(),
                "Open succeeded with mutated sealed message"
            );

            // Mutated public key → Open fails.
            let mutated_pk = mutate_array(&pk, mutation);
            assert!(
                open(&ctx, &sealed, &mutated_pk).expect("open").is_none(),
                "Open succeeded with mutated public key"
            );
        }
    }
}

/// Port of `FuzzMLDSA87FromHexSeedAndSigner`: hex-seed round-trip plus
/// signer round-trip. Rust analogue exercises the hex parsing path and
/// a sign / verify round-trip via `MlDsa87::from_hex_seed`.
#[test]
fn mldsa87_from_hex_seed_round_trips() {
    for seed in corpus_seeds() {
        let signer = MlDsa87::from_seed(seed);
        let hex_seed = signer.hex_seed();
        let round_trip = MlDsa87::from_hex_seed(&hex_seed).expect("round-trip hex seed must parse");
        assert_eq!(
            signer.public_key_bytes(),
            round_trip.public_key_bytes(),
            "hex seed round-trip changed the derived public key"
        );

        // Sign with the round-trip signer; verify under the original pk.
        let message = b"hex-seed-round-trip-message";
        let signature = round_trip.sign(b"ctx", message).expect("sign via round-trip");
        assert!(
            verify_bytes(b"ctx", message, &signature, &signer.public_key_bytes()).expect("verify"),
            "signature from round-trip signer did not verify under original pk"
        );

        // Hex-seed parser rejects malformed input.
        assert!(matches!(MlDsa87::from_hex_seed("not-hex"), Err(QrllibError::Hex(_))));
        assert!(matches!(
            MlDsa87::from_hex_seed("0x00"),
            Err(QrllibError::InvalidMlDsaSeedSize(_, _))
        ));
    }
}

// ============================================================
// Metamorphic property tests (port of metamorphic_fuzz_test.go)
// ============================================================

/// Port of `FuzzMetamorphicVerifyRejectsMauledPublicKey`.
#[test]
fn metamorphic_verify_rejects_mauled_public_key() {
    for seed in corpus_seeds() {
        for (ctx, message, mutation) in corpus_inputs() {
            let signer = MlDsa87::from_seed(seed);
            let signature = signer.sign(&ctx, &message).expect("sign");
            let pk = signer.public_key_bytes();
            assert!(verify_bytes(&ctx, &message, &signature, &pk).expect("baseline"));

            let mauled = flip_single_bit(&pk, mutation.0);
            let mut mauled_pk = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
            mauled_pk.copy_from_slice(&mauled);
            assert!(
                !verify_bytes(&ctx, &message, &signature, &mauled_pk).unwrap_or(false),
                "single-bit-mauled public key verified (bit={})",
                mutation.0
            );
        }
    }
}

/// Port of `FuzzMetamorphicVerifyRejectsMauledMessage`.
#[test]
fn metamorphic_verify_rejects_mauled_message() {
    for seed in corpus_seeds() {
        for (ctx, message, mutation) in corpus_inputs() {
            let signer = MlDsa87::from_seed(seed);
            let signature = signer.sign(&ctx, &message).expect("sign");
            let pk = signer.public_key_bytes();
            assert!(verify_bytes(&ctx, &message, &signature, &pk).expect("baseline"));

            let mauled_msg = flip_single_bit(&message, mutation.0);
            assert_ne!(mauled_msg, message, "message maul did not change input");
            assert!(
                !verify_bytes(&ctx, &mauled_msg, &signature, &pk).expect("verify mauled"),
                "single-bit-mauled message verified (bit={})",
                mutation.0
            );
        }
    }
}

/// Port of `FuzzMetamorphicVerifyRejectsMauledSignature`.
#[test]
fn metamorphic_verify_rejects_mauled_signature() {
    for seed in corpus_seeds() {
        for (ctx, message, mutation) in corpus_inputs() {
            let signer = MlDsa87::from_seed(seed);
            let signature = signer.sign(&ctx, &message).expect("sign");
            let pk = signer.public_key_bytes();
            assert!(verify_bytes(&ctx, &message, &signature, &pk).expect("baseline"));

            let mauled = flip_single_bit(&signature, mutation.0);
            let mut mauled_sig = [0_u8; ML_DSA_87_SIGNATURE_SIZE];
            mauled_sig.copy_from_slice(&mauled);
            assert!(
                !verify_bytes(&ctx, &message, &mauled_sig, &pk).expect("verify mauled"),
                "single-bit-mauled signature verified (bit={})",
                mutation.0
            );
        }
    }
}

/// Port of `FuzzMetamorphicDeterministicSigningChangesOnMauledMessage`.
/// Routes through `sign_deterministic` so the byte-equality property is
/// genuinely tested (default `sign` is hedged per TOB-QRLLIB-6, where
/// the assertion would hold trivially).
#[test]
fn metamorphic_deterministic_signing_changes_on_mauled_message() {
    for seed in corpus_seeds() {
        for (ctx, message, mutation) in corpus_inputs() {
            let signer = MlDsa87::from_seed(seed);
            let base_sig = signer.sign_deterministic(&ctx, &message).expect("base");

            let mauled_msg = flip_single_bit(&message, mutation.0);
            let mauled_sig = signer.sign_deterministic(&ctx, &mauled_msg).expect("sign mauled msg");

            assert_ne!(
                mauled_sig, base_sig,
                "deterministic signing collision after single-bit message maul (bit={})",
                mutation.0
            );
        }
    }
}

/// Port of `FuzzMetamorphicOpenRejectsMauledAttachedSignature`.
/// Restricts mauling to the attached-signature prefix (mirrors the Go
/// test which mauls only sigma and not the message suffix).
#[test]
fn metamorphic_open_rejects_mauled_attached_signature() {
    for seed in corpus_seeds() {
        for (ctx, message, mutation) in corpus_inputs() {
            let signer = MlDsa87::from_seed(seed);
            let sealed = signer.sign_attached(&ctx, &message).expect("sign_attached");
            let pk = signer.public_key_bytes();

            let opened = open(&ctx, &sealed, &pk).expect("baseline open").expect("baseline msg");
            assert_eq!(opened, message, "baseline sealed message did not round-trip");

            // Maul only the signature prefix.
            let prefix = &sealed[..ML_DSA_87_SIGNATURE_SIZE];
            let suffix = &sealed[ML_DSA_87_SIGNATURE_SIZE..];
            let mauled_prefix = flip_single_bit(prefix, mutation.0);
            let mut mauled_sealed = mauled_prefix.clone();
            mauled_sealed.extend_from_slice(suffix);

            assert!(
                open(&ctx, &mauled_sealed, &pk).expect("open mauled").is_none(),
                "single-bit-mauled attached signature opened successfully (bit={})",
                mutation.0
            );
        }
    }
}
