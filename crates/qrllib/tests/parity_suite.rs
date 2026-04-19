use qrllib::{
    DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_SIGNATURE_SIZE, Dilithium, ML_DSA_87_CRYPTO_SEED_SIZE,
    ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, dilithium_extract_message,
    dilithium_extract_signature, dilithium_open, extract_message, extract_signature,
    mldsa::verify_bytes, open, sphincsplus_extract_message, sphincsplus_extract_signature,
    sphincsplus_open, verify_dilithium_signature, verify_sphincsplus_signature,
};

const ML_DSA_C_TILDE_BYTES: usize = 64;
const ML_DSA_L: usize = 7;
const ML_DSA_POLY_Z_PACKED_BYTES: usize = 640;
const ML_DSA_OMEGA: usize = 75;
const ML_DSA_K: usize = 8;

#[test]
fn mldsa_canonicality_and_edge_cases_match_go_expectations() {
    let signer = MlDsa87::from_seed([11_u8; ML_DSA_87_CRYPTO_SEED_SIZE]);
    let public_key = signer.public_key_bytes();
    let context = b"ctx";
    let message = b"test message for canonicality";
    let signature = signer.sign(context, message).expect("signature");
    let hint_start = ML_DSA_C_TILDE_BYTES + ML_DSA_L * ML_DSA_POLY_Z_PACKED_BYTES;

    assert!(verify_bytes(context, message, &signature, &public_key).expect("verify"));

    for length in [
        0,
        1,
        ML_DSA_C_TILDE_BYTES / 2,
        ML_DSA_C_TILDE_BYTES,
        ML_DSA_C_TILDE_BYTES + (ML_DSA_POLY_Z_PACKED_BYTES / 2),
        ML_DSA_C_TILDE_BYTES + ML_DSA_L * ML_DSA_POLY_Z_PACKED_BYTES,
        ML_DSA_87_SIGNATURE_SIZE - 1,
    ] {
        let mut truncated = signature[..length].to_vec();
        truncated.extend_from_slice(message);
        assert!(
            open(context, &truncated, &public_key).expect("open truncated").is_none(),
            "length {length}"
        );
    }

    let mut corrupted_last_byte = signature;
    corrupted_last_byte[ML_DSA_87_SIGNATURE_SIZE - 1] ^= 1;
    assert!(!verify_bytes(context, message, &corrupted_last_byte, &public_key).expect("verify"));

    let mut cumulative_count_exceeds_omega = signature;
    cumulative_count_exceeds_omega[hint_start + ML_DSA_OMEGA] = (ML_DSA_OMEGA + 1) as u8;
    assert!(
        !verify_bytes(context, message, &cumulative_count_exceeds_omega, &public_key)
            .expect("verify")
    );

    let mut decreasing_counts = signature;
    decreasing_counts[hint_start + ML_DSA_OMEGA] = 3;
    decreasing_counts[hint_start + ML_DSA_OMEGA + 1] = 2;
    decreasing_counts[hint_start] = 10;
    decreasing_counts[hint_start + 1] = 20;
    decreasing_counts[hint_start + 2] = 30;
    assert!(!verify_bytes(context, message, &decreasing_counts, &public_key).expect("verify"));

    let mut non_increasing_indices = signature;
    non_increasing_indices[hint_start + ML_DSA_OMEGA] = 2;
    non_increasing_indices[hint_start] = 10;
    non_increasing_indices[hint_start + 1] = 10;
    assert!(!verify_bytes(context, message, &non_increasing_indices, &public_key).expect("verify"));

    let mut non_zero_padding = signature;
    for index in 0..ML_DSA_K {
        non_zero_padding[hint_start + ML_DSA_OMEGA + index] = 0;
    }
    non_zero_padding[hint_start] = 0xff;
    assert!(!verify_bytes(context, message, &non_zero_padding, &public_key).expect("verify"));

    let empty_signature = signer.sign(b"", b"").expect("empty signature");
    assert!(verify_bytes(b"", b"", &empty_signature, &public_key).expect("verify"));

    for size in [1024_usize, 64 * 1024] {
        let large_message = vec![0x5a; size];
        let signature = signer.sign(b"", &large_message).expect("large signature");
        assert!(verify_bytes(b"", &large_message, &signature, &public_key).expect("verify"));
    }

    let wrong_context = b"other";
    assert!(!verify_bytes(wrong_context, message, &signature, &public_key).expect("verify"));
}

#[test]
fn malformed_signature_helpers_do_not_panic_for_supported_stateless_schemes() {
    let mldsa_public_key = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
    let dilithium_public_key = [0_u8; DILITHIUM_PUBLIC_KEY_SIZE];
    let sphincs_public_key = [0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE];

    for length in [
        0_usize,
        1,
        16,
        ML_DSA_87_SIGNATURE_SIZE - 1,
        ML_DSA_87_SIGNATURE_SIZE,
        ML_DSA_87_SIGNATURE_SIZE + 33,
    ] {
        let input = vec![0xa5; length];
        let _ = extract_message(&input);
        let _ = extract_signature(&input);
        let _ = open(b"", &input, &mldsa_public_key);
        let signature = if length >= ML_DSA_87_SIGNATURE_SIZE {
            input[..ML_DSA_87_SIGNATURE_SIZE].to_vec()
        } else {
            input.clone()
        };
        let _ = verify_bytes(b"", b"", &signature, &mldsa_public_key);
    }

    for length in [
        0_usize,
        1,
        16,
        DILITHIUM_SIGNATURE_SIZE - 1,
        DILITHIUM_SIGNATURE_SIZE,
        DILITHIUM_SIGNATURE_SIZE + 33,
    ] {
        let input = vec![0x3c; length];
        let _ = dilithium_extract_message(&input);
        let _ = dilithium_extract_signature(&input);
        let _ = dilithium_open(&input, &dilithium_public_key);
        let signature = if length >= DILITHIUM_SIGNATURE_SIZE {
            input[..DILITHIUM_SIGNATURE_SIZE].to_vec()
        } else {
            input.clone()
        };
        let _ = verify_dilithium_signature(b"", &signature, &dilithium_public_key);
    }

    for length in [
        0_usize,
        1,
        16,
        SPHINCS_PLUS_256S_SIGNATURE_SIZE - 1,
        SPHINCS_PLUS_256S_SIGNATURE_SIZE,
        SPHINCS_PLUS_256S_SIGNATURE_SIZE + 33,
    ] {
        let input = vec![0x7e; length];
        let _ = sphincsplus_extract_message(&input);
        let _ = sphincsplus_extract_signature(&input);
        let _ = sphincsplus_open(&input, &sphincs_public_key);
        let signature = if length >= SPHINCS_PLUS_256S_SIGNATURE_SIZE {
            input[..SPHINCS_PLUS_256S_SIGNATURE_SIZE].to_vec()
        } else {
            input.clone()
        };
        let _ = verify_sphincsplus_signature(b"", &signature, &sphincs_public_key);
    }
}

#[test]
fn dilithium_edge_case_verification_matches_go_expectations() {
    let signer = Dilithium::from_seed([9_u8; 32]);
    let public_key = signer.public_key_bytes();
    let message = b"test message";
    let signature = signer.sign(message).expect("signature");

    assert!(verify_dilithium_signature(message, &signature, &public_key));
    assert!(!verify_dilithium_signature(message, &[0_u8; DILITHIUM_SIGNATURE_SIZE], &public_key));
    assert!(!verify_dilithium_signature(
        message,
        &vec![0xff; DILITHIUM_SIGNATURE_SIZE],
        &public_key
    ));

    let mut corrupted = signature;
    for index in (0..corrupted.len()).step_by((corrupted.len() / 10).max(1)) {
        corrupted[index] ^= 0xff;
        assert!(!verify_dilithium_signature(message, &corrupted, &public_key));
        corrupted[index] ^= 0xff;
    }

    let empty_signature = signer.sign(b"").expect("empty signature");
    assert!(verify_dilithium_signature(b"", &empty_signature, &public_key));
}
