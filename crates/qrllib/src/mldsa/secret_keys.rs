//! Secret-key encoding checks shared in rule with go-qrllib and qrypto.js.
//!
//! A packed secret key is `rho (32) || K (32) || tr (64) || s1 (L*96) ||
//! s2 (K*96) || t0 (K*416)`. `s1` and `s2` coefficients are 3-bit fields
//! holding `ETA - v`, packed eight per three bytes little-endian, so 0..=4
//! are the encodings key generation writes and 5, 6, 7 decode to -3, -4, -5.
//! `t0` coefficients are 13-bit fields holding `2^(D-1) - v`; every value
//! decodes into the Power2Round range. This module lives in-crate because the
//! primitive-level check in `crypto_sign_signature` is behind
//! [`validate_mldsa_secret_key`] on every public path and can only be reached
//! directly.

use super::{
    ETA, K, L, ML_DSA_87_CRYPTO_SEED_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE,
    ML_DSA_87_SIGNATURE_SIZE, MlDsa87, N, POLY_ETA_PACKED_BYTES, POLY_T0_PACKED_BYTES, Poly,
    TR_BYTES, crypto_sign_signature, poly_t0_pack, sign_with_secret_key,
    sign_with_secret_key_deterministic, validate_mldsa_secret_key, verify_bytes,
};
use crate::QrllibError;

const S1_OFFSET: usize = 2 * ML_DSA_87_CRYPTO_SEED_SIZE + TR_BYTES;
const S2_OFFSET: usize = S1_OFFSET + L * POLY_ETA_PACKED_BYTES;
const T0_OFFSET: usize = S2_OFFSET + K * POLY_ETA_PACKED_BYTES;
const CONTEXT: &[u8] = b"ZOND";
const MESSAGE: &[u8] = b"secret key validation";
const VALID_FIELDS: [u8; 5] = [0, 1, 2, 3, 4];
const INVALID_FIELDS: [u8; 3] = [5, 6, 7];

fn keypair(seed_byte: u8) -> ([u8; ML_DSA_87_PUBLIC_KEY_SIZE], [u8; ML_DSA_87_SECRET_KEY_SIZE]) {
    let signer = MlDsa87::from_seed([seed_byte; ML_DSA_87_CRYPTO_SEED_SIZE]).expect("keypair");
    (signer.public_key_bytes(), *signer.secret_key_bytes())
}

/// Overwrites the 3-bit field of coefficient `index` (0..N) of the eta-packed
/// polynomial starting at `offset`. Field `k` occupies bits `3k..3k+2` of the
/// little-endian bit stream, so it spans at most two bytes.
fn set_eta_field(sk: &mut [u8], offset: usize, index: usize, field: u8) {
    let bit = 3 * index;
    let byte = offset + bit / 8;
    let shift = bit % 8;
    let mut word = u16::from(sk[byte]) | (u16::from(sk[byte + 1]) << 8);
    word &= !(7_u16 << shift);
    word |= u16::from(field) << shift;
    sk[byte] = word.to_le_bytes()[0];
    sk[byte + 1] = word.to_le_bytes()[1];
}

/// Single-line so the `matches!` expansion (whose false arm never runs) does
/// not leave an uncovered region on a multi-line assertion.
fn is_encoding_error(result: &crate::Result<()>) -> bool {
    matches!(result, Err(QrllibError::InvalidMlDsaSecretKeyEncoding))
}

fn with_eta_field(
    sk: &[u8; ML_DSA_87_SECRET_KEY_SIZE],
    offset: usize,
    index: usize,
    field: u8,
) -> [u8; ML_DSA_87_SECRET_KEY_SIZE] {
    let mut copy = *sk;
    set_eta_field(&mut copy, offset, index, field);
    copy
}

/// `t0` with every coefficient at full magnitude (4096 or -4095, signs from a
/// fixed xorshift32 stream). It passes validation, since `t0` has no invalid
/// encoding, and is the one field a caller can shape to slow signing down:
/// `c·t0` then asks for about 100 hints per attempt against the OMEGA = 75 a
/// signature can carry, so roughly 99 attempts in 100 are rejected on the
/// hint count. The loop still ends within the budget.
fn full_magnitude_t0(sk: &[u8; ML_DSA_87_SECRET_KEY_SIZE]) -> [u8; ML_DSA_87_SECRET_KEY_SIZE] {
    let mut crafted = *sk;
    let mut poly = Poly::default();
    let mut x = 0x9e37_79b9_u32;
    for i in 0..K {
        for coeff in poly.coeffs.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *coeff = if x & 1 == 1 { 4096 } else { -4095 };
        }
        let start = T0_OFFSET + i * POLY_T0_PACKED_BYTES;
        poly_t0_pack(&mut crafted[start..start + POLY_T0_PACKED_BYTES], &poly);
    }
    crafted
}

#[test]
fn layout_constants_match_the_packed_key() {
    assert_eq!(ETA, 2);
    assert_eq!(T0_OFFSET + K * POLY_T0_PACKED_BYTES, ML_DSA_87_SECRET_KEY_SIZE);
}

#[test]
fn accepts_a_generated_key() {
    let (_, sk) = keypair(0x42);
    assert!(validate_mldsa_secret_key(&sk).is_ok());
}

#[test]
fn accepts_every_encoding_0_to_4_and_rejects_5_6_7_at_the_corners_of_s1_and_s2() {
    let (_, sk) = keypair(0x42);
    let corners = [
        (S1_OFFSET, 0),
        (S1_OFFSET + (L - 1) * POLY_ETA_PACKED_BYTES, N - 1),
        (S2_OFFSET, 0),
        (S2_OFFSET + (K - 1) * POLY_ETA_PACKED_BYTES, N - 1),
    ];
    for (offset, index) in corners {
        for field in VALID_FIELDS {
            assert!(
                validate_mldsa_secret_key(&with_eta_field(&sk, offset, index, field)).is_ok(),
                "offset {offset} index {index} field {field}"
            );
        }
        for field in INVALID_FIELDS {
            assert!(
                is_encoding_error(&validate_mldsa_secret_key(&with_eta_field(
                    &sk, offset, index, field
                ))),
                "offset {offset} index {index} field {field}"
            );
        }
    }
}

#[test]
fn checks_every_s1_and_s2_field() {
    let (_, sk) = keypair(0x42);
    for poly in 0..(L + K) {
        let offset = S1_OFFSET + poly * POLY_ETA_PACKED_BYTES;
        for index in 0..N {
            assert!(
                is_encoding_error(&validate_mldsa_secret_key(&with_eta_field(
                    &sk, offset, index, 7
                ))),
                "poly {poly} index {index}"
            );
        }
    }
}

#[test]
fn does_not_examine_rho_key_tr_or_t0() {
    let (_, sk) = keypair(0x42);
    for fill in [0x00_u8, 0xff] {
        let mut head = sk;
        head[..S1_OFFSET].fill(fill);
        assert!(validate_mldsa_secret_key(&head).is_ok());
        let mut tail = sk;
        tail[T0_OFFSET..].fill(fill);
        assert!(validate_mldsa_secret_key(&tail).is_ok());
    }
}

#[test]
fn public_signing_paths_reject_an_invalid_encoding() {
    let (_, sk) = keypair(0x07);
    let invalid = with_eta_field(&sk, S2_OFFSET + 3 * POLY_ETA_PACKED_BYTES, 17, 5);
    assert!(is_encoding_error(&sign_with_secret_key(CONTEXT, MESSAGE, &invalid).map(|_| ())));
    assert!(is_encoding_error(
        &sign_with_secret_key_deterministic(CONTEXT, MESSAGE, &invalid).map(|_| ())
    ));
    let rendered = QrllibError::InvalidMlDsaSecretKeyEncoding.to_string();
    assert!(rendered.contains("s1 or s2"), "{rendered}");
}

#[test]
fn the_primitive_rejects_an_invalid_encoding_before_writing_a_signature() {
    // `sign_with_secret_key` validates first; call the primitive directly to
    // exercise the check it applies for every path, public or future.
    let (_, sk) = keypair(0x07);
    let invalid = with_eta_field(&sk, S1_OFFSET, 0, 6);
    let mut signature = [0_u8; ML_DSA_87_SIGNATURE_SIZE];
    assert!(is_encoding_error(&crypto_sign_signature(
        &mut signature,
        CONTEXT,
        MESSAGE,
        &invalid,
        false
    )));
    assert!(signature.iter().all(|byte| *byte == 0));
}

#[test]
fn a_full_magnitude_t0_passes_validation_and_signing_still_completes() {
    let (pk, sk) = keypair(0x13);
    let crafted = full_magnitude_t0(&sk);
    assert!(validate_mldsa_secret_key(&crafted).is_ok());
    let signature = sign_with_secret_key_deterministic(CONTEXT, MESSAGE, &crafted)
        .expect("bounded loop completes");
    // The hints were computed from the wrong t0, so the signature does not
    // verify under the honest public key.
    let public_key = super::PublicKey::from_bytes(&pk).expect("honest key");
    assert!(!verify_bytes(CONTEXT, MESSAGE, &signature, &public_key).expect("well-formed"));
}

#[test]
fn control_the_generated_key_signs_and_verifies() {
    let (pk, sk) = keypair(0x13);
    let signature = sign_with_secret_key_deterministic(CONTEXT, MESSAGE, &sk).expect("sign");
    let public_key = super::PublicKey::from_bytes(&pk).expect("honest key");
    assert!(verify_bytes(CONTEXT, MESSAGE, &signature, &public_key).expect("well-formed"));
}
