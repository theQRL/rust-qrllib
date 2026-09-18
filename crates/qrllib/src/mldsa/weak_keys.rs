//! Weak-key rule tests shared with go-qrllib, qrypto.js and wallet.js.
//!
//! `testdata/weak_public_key_vectors.json` is the file every QRL client runs.
//! For each vector this module checks the verdict of
//! [`validate_mldsa_public_key`] and [`PublicKey::from_bytes`], the number of
//! large `t1` coefficients, and the behaviour of the FIPS 204 primitive: keys
//! flagged `zeroHintForgeryVerifies` accept the `(z = 0, h = 0,
//! c~ = H(mu || w1Encode(0)))` signature (the behaviour that makes the rule
//! necessary), and accepted keys reject it with and without hints. It lives
//! in-crate, next to the ACVP and Wycheproof harnesses, because driving the
//! primitive on a weak key needs the `#[cfg(test)]`-only
//! [`PublicKey::from_bytes_unchecked`]. See [`validate_mldsa_public_key`] for
//! the rule and its derivation.

use super::{
    C_TILDE_BYTES, CRH_BYTES, D, GAMMA2, K, ML_DSA_87_CRYPTO_SEED_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE,
    ML_DSA_87_SIGNATURE_SIZE, MlDsa87, N, OMEGA, POLY_W1_PACKED_BYTES, Poly, PolyVecK, PolyVecL,
    PublicKey, Q, T1_LARGE_HIGH, T1_LARGE_HIGH_BELOW_HALF, T1_LARGE_LOW, T1_LARGE_LOW_ABOVE_HALF,
    T1_MIN_LARGE, TR_BYTES, context_prefix, count_large_t1, crypto_sign_verify_mldsa, decompose,
    pack_pk, pack_sig, poly_challenge, poly_ntt, poly_vec_k_cadd_q, poly_vec_k_inv_ntt_to_mont,
    poly_vec_k_ntt, poly_vec_k_point_wise_poly_montgomery, poly_vec_k_reduce, poly_vec_k_shift_l,
    poly_vec_k_sub, shake256, shake256_many, unpack_pk, use_hint, validate_mldsa_public_key,
    verify_bytes,
};
use crate::QrllibError;
use serde::Deserialize;

const VECTORS: &str = include_str!("testdata/weak_public_key_vectors.json");

/// Context and message go-qrllib runs the shared vectors under. The primitive
/// is byte-identical across clients, so using the same pair reproduces the
/// `zeroHintForgeryVerifies` observations exactly.
const CONTEXT: &[u8] = b"ZOND";
const MESSAGE: &[u8] = b"shared weak-key vectors";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WeakKeyVectorFile {
    parameter_set: String,
    t1_coefficients: usize,
    large_low: i32,
    large_high_below_half: i32,
    large_low_above_half: i32,
    large_high: i32,
    min_large_coefficients: usize,
    vectors: Vec<WeakKeyVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WeakKeyVector {
    name: String,
    pk: String,
    large_coefficients: usize,
    expected: Verdict,
    zero_hint_forgery_verifies: bool,
}

/// Parsed strictly: any value other than `accept` / `weak` fails the parse,
/// so the vector loop needs no unreachable "unknown verdict" arm.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Verdict {
    Accept,
    Weak,
}

/// The signature anyone can compute from public data only:
/// `pre = 0x00 || len(ctx) || ctx`; `tr = SHAKE256(pk)[..64]`;
/// `mu = SHAKE256(tr || pre || msg)[..64]`;
/// `c~ = SHAKE256(mu || w1Encode(0))[..64]`; `signature = c~ || z || h` with
/// `z = 0` and `h = 0`, produced by the crate's own `pack_sig`. Under a key
/// for which every coefficient of `c·2^D·t1` has `HighBits` 0 it verifies for
/// any message.
pub(super) fn forge_zero_hint_signature(
    context: &[u8],
    message: &[u8],
    public_key: &[u8; ML_DSA_87_PUBLIC_KEY_SIZE],
) -> [u8; ML_DSA_87_SIGNATURE_SIZE] {
    let prefix = context_prefix(context).expect("context");
    let mut tr = [0_u8; TR_BYTES];
    shake256(&mut tr, public_key);
    let mut mu = [0_u8; CRH_BYTES];
    shake256_many(&mut mu, &[&tr, &prefix, message]);
    let mut challenge = [0_u8; C_TILDE_BYTES];
    shake256_many(&mut challenge, &[&mu, &[0_u8; K * POLY_W1_PACKED_BYTES]]);
    let mut signature = [0_u8; ML_DSA_87_SIGNATURE_SIZE];
    pack_sig(&mut signature, &challenge, &PolyVecL::default(), &PolyVecK::default());
    signature
}

/// The strongest signature in the `z = 0` family: recomputes
/// `w = -c·2^D·t1` exactly as the verifier does, sets a hint on every
/// coefficient a single hint can pull back to `HighBits` 0, and gives up if
/// any coefficient cannot be corrected or more than `OMEGA` hints are needed.
/// Returns whether the signature verified at the primitive.
pub(super) fn forge_with_hints(
    context: &[u8],
    message: &[u8],
    public_key: &[u8; ML_DSA_87_PUBLIC_KEY_SIZE],
) -> bool {
    let zero_hint = forge_zero_hint_signature(context, message, public_key);
    let mut challenge = [0_u8; C_TILDE_BYTES];
    challenge.copy_from_slice(&zero_hint[..C_TILDE_BYTES]);

    let mut rho = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    let mut t1 = PolyVecK::default();
    unpack_pk(&mut rho, &mut t1, public_key);
    let mut challenge_poly = Poly::default();
    poly_challenge(&mut challenge_poly, &challenge);
    poly_ntt(&mut challenge_poly);
    poly_vec_k_shift_l(&mut t1);
    poly_vec_k_ntt(&mut t1);
    let t1_current = t1;
    poly_vec_k_point_wise_poly_montgomery(&mut t1, &challenge_poly, &t1_current);
    // With z = 0 the verifier's A·z term is zero, so w = 0 - c·2^D·t1.
    let mut w = PolyVecK::default();
    poly_vec_k_sub(&mut w, &PolyVecK::default(), &t1);
    poly_vec_k_reduce(&mut w);
    poly_vec_k_inv_ntt_to_mont(&mut w);
    poly_vec_k_cadd_q(&mut w);

    let mut hints = PolyVecK::default();
    let mut hint_count = 0_usize;
    for (poly_index, poly) in w.vec.iter().enumerate() {
        for (index, &coefficient) in poly.coeffs.iter().enumerate() {
            let mut low = 0_i32;
            if decompose(&mut low, coefficient) == 0 {
                continue;
            }
            if use_hint(coefficient, 1) != 0 {
                return false;
            }
            hints.vec[poly_index].coeffs[index] = 1;
            hint_count += 1;
        }
    }
    if hint_count > OMEGA {
        return false;
    }
    let mut signature = [0_u8; ML_DSA_87_SIGNATURE_SIZE];
    pack_sig(&mut signature, &challenge, &PolyVecL::default(), &hints);
    crypto_sign_verify_mldsa(&signature, context, message, public_key).expect("primitive")
}

fn zero_hint_forgery_verifies(public_key: &[u8; ML_DSA_87_PUBLIC_KEY_SIZE]) -> bool {
    let signature = forge_zero_hint_signature(CONTEXT, MESSAGE, public_key);
    crypto_sign_verify_mldsa(&signature, CONTEXT, MESSAGE, public_key).expect("primitive")
}

/// Packs a key with a fixed `rho` around the given `t1`.
fn pack_key(t1: &PolyVecK) -> [u8; ML_DSA_87_PUBLIC_KEY_SIZE] {
    let mut public_key = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
    pack_pk(&mut public_key, &[0x2a_u8; ML_DSA_87_CRYPTO_SEED_SIZE], t1);
    public_key
}

/// The four bounds and the minimum are derived from the parameter set; this
/// pins the literals the shared vector file, go-qrllib, qrypto.js and
/// wallet.js use.
#[test]
fn weak_key_rule_constants_match_the_parameter_set() {
    assert_eq!(Q, 8_380_417);
    assert_eq!(D, 13);
    assert_eq!(GAMMA2, 261_888);
    assert_eq!(OMEGA, 75);

    assert_eq!(T1_LARGE_LOW, 96);
    assert_eq!(T1_LARGE_HIGH_BELOW_HALF, 415);
    assert_eq!(T1_LARGE_LOW_ABOVE_HALF, 608);
    assert_eq!(T1_LARGE_HIGH, 927);
    assert_eq!(T1_MIN_LARGE, 76);

    // Each bound is the first (or last) coefficient whose contribution, as
    // 2^D·v centered modulo q or as half of 2^(D+1)·v centered modulo q,
    // exceeds 3·GAMMA2.
    let three_gamma2 = 3 * GAMMA2;
    assert!((T1_LARGE_LOW - 1) * (1 << D) <= three_gamma2);
    assert!(T1_LARGE_LOW * (1 << D) > three_gamma2);
    assert!(Q - (T1_LARGE_HIGH + 1) * (1 << D) <= three_gamma2);
    assert!(Q - T1_LARGE_HIGH * (1 << D) > three_gamma2);
    // On the 2^-1 side the contribution is (q - 2^(D+1)·v) / 2 for v just
    // below q / 2^(D+1) and (2^(D+1)·v - q) / 2 just above it.
    assert!((Q - (T1_LARGE_HIGH_BELOW_HALF + 1) * (1 << (D + 1))) / 2 <= three_gamma2);
    assert!((Q - T1_LARGE_HIGH_BELOW_HALF * (1 << (D + 1))) / 2 > three_gamma2);
    assert!(((T1_LARGE_LOW_ABOVE_HALF - 1) * (1 << (D + 1)) - Q) / 2 <= three_gamma2);
    assert!((T1_LARGE_LOW_ABOVE_HALF * (1 << (D + 1)) - Q) / 2 > three_gamma2);
}

#[test]
fn shared_weak_key_vectors_match_rule_count_and_primitive_behaviour() {
    let file: WeakKeyVectorFile =
        serde_json::from_str(VECTORS).expect("parse weak_public_key_vectors.json");
    assert_eq!(file.parameter_set, "ML-DSA-87");
    assert_eq!(file.t1_coefficients, K * N);
    assert_eq!(
        (
            file.large_low,
            file.large_high_below_half,
            file.large_low_above_half,
            file.large_high,
            file.min_large_coefficients,
        ),
        (
            T1_LARGE_LOW,
            T1_LARGE_HIGH_BELOW_HALF,
            T1_LARGE_LOW_ABOVE_HALF,
            T1_LARGE_HIGH,
            T1_MIN_LARGE
        ),
        "vector file constants do not match the implementation"
    );
    assert!(!file.vectors.is_empty(), "no vectors");

    let mut accepted = 0_usize;
    let mut weak = 0_usize;
    let mut forgeries_verified = 0_usize;
    for vector in &file.vectors {
        let name = vector.name.as_str();
        let bytes = hex::decode(&vector.pk).unwrap_or_else(|e| panic!("{name}: pk hex: {e}"));
        assert_eq!(bytes.len(), ML_DSA_87_PUBLIC_KEY_SIZE, "{name}: pk length");
        let mut public_key = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&bytes);

        // (b) the count behind the verdict.
        assert_eq!(
            count_large_t1(&public_key[ML_DSA_87_CRYPTO_SEED_SIZE..]),
            vector.large_coefficients,
            "{name}: large coefficient count"
        );

        // (a) the verdict, through both entry points.
        let verdict = validate_mldsa_public_key(&public_key);
        let constructed = PublicKey::from_bytes(&public_key);
        match vector.expected {
            Verdict::Accept => {
                verdict.unwrap_or_else(|e| panic!("{name}: expected accept, got {e}"));
                let key =
                    constructed.unwrap_or_else(|e| panic!("{name}: expected accept, got {e}"));
                assert_eq!(key.as_bytes(), &public_key, "{name}: constructed key bytes");
                // (d) an accepted key admits neither the zero-hint signature
                // nor the strongest hinted one.
                assert!(
                    !zero_hint_forgery_verifies(&public_key),
                    "{name}: accepted key admits the zero-hint forgery"
                );
                assert!(
                    !forge_with_hints(CONTEXT, MESSAGE, &public_key),
                    "{name}: accepted key admits the hinted forgery"
                );
                accepted += 1;
            }
            Verdict::Weak => {
                assert!(
                    matches!(verdict, Err(QrllibError::WeakPublicKey)),
                    "{name}: expected WeakPublicKey, got {verdict:?}"
                );
                assert!(
                    matches!(constructed, Err(QrllibError::WeakPublicKey)),
                    "{name}: expected WeakPublicKey from from_bytes, got {constructed:?}"
                );
                weak += 1;
            }
        }

        // (c) the FIPS 204 behaviour the vector documents: the primitive
        // accepts the zero-hint signature, and so does the public verifier
        // when handed the unchecked key.
        if vector.zero_hint_forgery_verifies {
            assert!(
                zero_hint_forgery_verifies(&public_key),
                "{name}: primitive rejected the zero-hint forgery this vector documents"
            );
            let signature = forge_zero_hint_signature(CONTEXT, MESSAGE, &public_key);
            assert!(
                verify_bytes(
                    CONTEXT,
                    MESSAGE,
                    &signature,
                    &PublicKey::from_bytes_unchecked(public_key)
                )
                .expect("verify"),
                "{name}: verify_bytes rejected the zero-hint forgery under the unchecked key"
            );
            forgeries_verified += 1;
        }
    }
    eprintln!(
        "weak-key vectors: {} total, {accepted} accepted, {weak} weak, {forgeries_verified} zero-hint forgeries verified at the primitive",
        file.vectors.len()
    );
    assert!(accepted > 0 && weak > 0 && forgeries_verified > 0, "vector file exercises every arm");
}

/// The single-coefficient bands the rule is built on, matching go-qrllib's
/// `TestValidatePublicKey_HintBands`: `[0, 31]` and `[992, 1023]` forge with
/// no hints, `[32, 63]` and `[960, 991]` forge with hints, everything from 64
/// to 959 does not. A single coefficient is never enough for the rule, so
/// every one of these keys is rejected.
#[test]
fn single_coefficient_hint_bands_match_go_qrllib() {
    let context = b"ZOND";
    let message = b"band check";
    let cases: [(i32, bool, bool); 13] = [
        (31, true, true),
        (32, false, true),
        (63, false, true),
        (64, false, false),
        (95, false, false),
        (96, false, false),
        (927, false, false),
        (928, false, false),
        (959, false, false),
        (960, false, true),
        (991, false, true),
        (992, true, true),
        (1023, true, true),
    ];
    for (value, no_hints, with_hints) in cases {
        let mut t1 = PolyVecK::default();
        t1.vec[0].coeffs[0] = value;
        let public_key = pack_key(&t1);
        let signature = forge_zero_hint_signature(context, message, &public_key);
        assert_eq!(
            crypto_sign_verify_mldsa(&signature, context, message, &public_key).expect("primitive"),
            no_hints,
            "v={value}: zero-hint forgery"
        );
        assert_eq!(
            forge_with_hints(context, message, &public_key),
            with_hints,
            "v={value}: hinted forgery"
        );
        assert!(
            matches!(validate_mldsa_public_key(&public_key), Err(QrllibError::WeakPublicKey)),
            "v={value}: single coefficient accepted"
        );
    }

    // Two hint-correctable coefficients in different polynomials need
    // 2 * TAU = 120 hints, more than the OMEGA = 75 the signature can carry.
    let mut t1 = PolyVecK::default();
    t1.vec[0].coeffs[0] = 32;
    t1.vec[1].coeffs[0] = 32;
    let public_key = pack_key(&t1);
    assert!(!forge_with_hints(context, message, &public_key), "120 hints exceed OMEGA");
}

/// Exercises the count at every band edge, in every polynomial and at the
/// first and last coefficient positions, and checks that `rho` plays no part.
#[test]
fn count_large_t1_reads_every_coefficient_and_ignores_rho() {
    for (value, large) in [
        (0, false),
        (T1_LARGE_LOW - 1, false),
        (T1_LARGE_LOW, true),
        (T1_LARGE_HIGH_BELOW_HALF, true),
        (T1_LARGE_HIGH_BELOW_HALF + 1, false),
        (511, false),
        (512, false),
        (T1_LARGE_LOW_ABOVE_HALF - 1, false),
        (T1_LARGE_LOW_ABOVE_HALF, true),
        (T1_LARGE_HIGH, true),
        (T1_LARGE_HIGH + 1, false),
        (1023, false),
    ] {
        for (poly_index, index) in [(0, 0), (K / 2, N / 2), (K - 1, N - 1)] {
            let mut t1 = PolyVecK::default();
            t1.vec[poly_index].coeffs[index] = value;
            let public_key = pack_key(&t1);
            assert_eq!(
                count_large_t1(&public_key[ML_DSA_87_CRYPTO_SEED_SIZE..]),
                usize::from(large),
                "v={value} at ({poly_index}, {index})"
            );
        }
    }

    // Exactly T1_MIN_LARGE large coefficients, spread over every polynomial
    // and including the first and last positions of t1, is enough; one fewer
    // is not. The verdict is the same whatever rho holds.
    let mut t1 = PolyVecK::default();
    t1.vec[0].coeffs[0] = T1_LARGE_LOW;
    t1.vec[K - 1].coeffs[N - 1] = T1_LARGE_HIGH;
    for i in 0..T1_MIN_LARGE - 2 {
        t1.vec[i % K].coeffs[1 + i] = T1_LARGE_LOW_ABOVE_HALF;
    }
    let mut ascending = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    for (index, byte) in ascending.iter_mut().enumerate() {
        *byte = index as u8 + 1;
    }
    for rho in
        [[0x00_u8; ML_DSA_87_CRYPTO_SEED_SIZE], [0xff; ML_DSA_87_CRYPTO_SEED_SIZE], ascending]
    {
        let mut public_key = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
        pack_pk(&mut public_key, &rho, &t1);
        assert_eq!(count_large_t1(&public_key[ML_DSA_87_CRYPTO_SEED_SIZE..]), T1_MIN_LARGE);
        let key = PublicKey::from_bytes(&public_key).expect("exactly the minimum is accepted");
        assert_eq!(key.as_bytes(), &public_key);

        let mut one_short = t1;
        one_short.vec[K - 1].coeffs[N - 1] = T1_LARGE_HIGH + 1;
        pack_pk(&mut public_key, &rho, &one_short);
        assert_eq!(count_large_t1(&public_key[ML_DSA_87_CRYPTO_SEED_SIZE..]), T1_MIN_LARGE - 1);
        assert!(matches!(PublicKey::from_bytes(&public_key), Err(QrllibError::WeakPublicKey)));
    }
}

/// Keys generated from fixed seeds pass with a wide margin over the minimum,
/// matching go-qrllib's `TestValidatePublicKey_HonestKeysPass`.
#[test]
fn honest_keys_pass_with_a_wide_margin() {
    let mut min_count = K * N;
    for i in 0..64_u8 {
        let mut seed = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
        for (j, byte) in seed.iter_mut().enumerate() {
            *byte = i.wrapping_mul(7).wrapping_add(j as u8);
        }
        let signer = MlDsa87::from_seed(seed).unwrap_or_else(|e| panic!("seed {i}: {e}"));
        let public_key = signer.public_key_bytes();
        validate_mldsa_public_key(&public_key)
            .unwrap_or_else(|e| panic!("seed {i}: honest key rejected: {e}"));
        min_count = min_count.min(count_large_t1(&public_key[ML_DSA_87_CRYPTO_SEED_SIZE..]));
    }
    assert!(
        min_count >= 1000,
        "honest keys have a minimum of {min_count} large coefficients; expected well above 1000"
    );
}
