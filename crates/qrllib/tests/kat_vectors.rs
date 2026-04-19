use qrllib::{
    DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_SECRET_KEY_SIZE, DILITHIUM_SIGNATURE_SIZE, Dilithium,
    ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
    SPHINCS_PLUS_256S_SECRET_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, SphincsPlus256s,
    dilithium_extract_message, dilithium_extract_signature, dilithium_open, extract_message,
    extract_signature, mldsa::verify_bytes, open, sign_dilithium_with_secret_key,
    sphincsplus_extract_message, sphincsplus_extract_signature, sphincsplus_open,
    verify_dilithium_signature, verify_sphincsplus_signature,
};

struct DilithiumKatVector {
    name: &'static str,
    seed: &'static str,
    message: &'static str,
}

struct MlDsaKatVector {
    name: &'static str,
    seed: &'static str,
    message: &'static str,
    context: &'static str,
}

const DILITHIUM_KAT_VECTORS: &[DilithiumKatVector] = &[
    DilithiumKatVector {
        name: "zero_seed",
        seed: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "",
    },
    DilithiumKatVector {
        name: "incremental_seed",
        seed: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        message: "48656c6c6f2c20576f726c6421",
    },
    DilithiumKatVector {
        name: "random_seed_1",
        seed: "deadbeefcafebabe0123456789abcdef00112233445566778899aabbccddeeff",
        message: "54657374206d65737361676520666f72204b415420766572696669636174696f6e",
    },
];

const MLDSA_KAT_VECTORS: &[MlDsaKatVector] = &[
    MlDsaKatVector {
        name: "zero_seed",
        seed: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "",
        context: "",
    },
    MlDsaKatVector {
        name: "incremental_seed",
        seed: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        message: "48656c6c6f2c20576f726c6421",
        context: "5a4f4e44",
    },
    MlDsaKatVector {
        name: "random_seed_1",
        seed: "deadbeefcafebabe0123456789abcdef00112233445566778899aabbccddeeff",
        message: "54657374206d65737361676520666f72204b415420766572696669636174696f6e",
        context: "",
    },
];

const SPHINCS_KAT_SEED: &str = concat!(
    "000102030405060708090a0b0c0d0e0f",
    "101112131415161718191a1b1c1d1e1f",
    "202122232425262728292a2b2c2d2e2f",
    "303132333435363738393a3b3c3d3e3f",
    "404142434445464748494a4b4c4d4e4f",
    "505152535455565758595a5b5c5d5e5f"
);
const SPHINCS_KAT_MESSAGE: &str = "48656c6c6f2c20576f726c6421";

fn decode_hex_array<const N: usize>(value: &str) -> [u8; N] {
    let bytes = hex::decode(value).expect("hex input");
    assert_eq!(bytes.len(), N, "hex length");
    let mut output = [0_u8; N];
    output.copy_from_slice(&bytes);
    output
}

fn decode_hex_vec(value: &str) -> Vec<u8> {
    hex::decode(value).expect("hex input")
}

#[test]
fn dilithium_known_answer_vectors_cover_deterministic_api_contracts() {
    assert_eq!(DILITHIUM_PUBLIC_KEY_SIZE, 2592);
    assert_eq!(DILITHIUM_SECRET_KEY_SIZE, 4896);
    assert_eq!(DILITHIUM_SIGNATURE_SIZE, 4595);

    for vector in DILITHIUM_KAT_VECTORS {
        let seed = decode_hex_array::<32>(vector.seed);
        let message = decode_hex_vec(vector.message);

        let signer_a = Dilithium::from_seed(seed);
        let signer_b = Dilithium::from_seed(seed);
        assert_eq!(signer_a.public_key_bytes(), signer_b.public_key_bytes(), "{}", vector.name);
        assert_eq!(signer_a.secret_key_bytes(), signer_b.secret_key_bytes(), "{}", vector.name);

        let imported = Dilithium::from_hex_seed(&signer_a.hex_seed()).expect("hex import");
        assert_eq!(imported.public_key_bytes(), signer_a.public_key_bytes(), "{}", vector.name);

        let signature_a = signer_a.sign(&message).expect("signature a");
        let signature_b = signer_a.sign(&message).expect("signature b");
        assert_eq!(signature_a, signature_b, "{}", vector.name);
        assert!(
            verify_dilithium_signature(&message, &signature_a, &signer_a.public_key_bytes()),
            "{}",
            vector.name
        );

        let signature_from_sk =
            sign_dilithium_with_secret_key(&message, &signer_a.secret_key_bytes())
                .expect("sign with secret key");
        assert_eq!(signature_a, signature_from_sk, "{}", vector.name);

        let mut sealed = signature_from_sk.to_vec();
        sealed.extend_from_slice(&message);
        assert_eq!(
            dilithium_extract_signature(&sealed).expect("sealed signature"),
            signature_from_sk.as_slice(),
            "{}",
            vector.name
        );
        assert_eq!(
            dilithium_extract_message(&sealed).expect("sealed message"),
            message.as_slice(),
            "{}",
            vector.name
        );
        assert_eq!(
            dilithium_open(&sealed, &signer_a.public_key_bytes()).expect("opened"),
            message,
            "{}",
            vector.name
        );

        let wrong_message = if message.is_empty() {
            vec![0x42]
        } else {
            let mut tampered = message.clone();
            tampered[0] ^= 0xff;
            tampered
        };
        assert!(
            !verify_dilithium_signature(&wrong_message, &signature_a, &signer_a.public_key_bytes()),
            "{}",
            vector.name
        );
    }

    let seed_a = decode_hex_array::<32>(DILITHIUM_KAT_VECTORS[0].seed);
    let seed_b = decode_hex_array::<32>(DILITHIUM_KAT_VECTORS[1].seed);
    let signer_a = Dilithium::from_seed(seed_a);
    let signer_b = Dilithium::from_seed(seed_b);
    assert_ne!(signer_a.public_key_bytes(), signer_b.public_key_bytes());
    assert_ne!(signer_a.secret_key_bytes(), signer_b.secret_key_bytes());

    let mut zeroized = Dilithium::from_seed(seed_a);
    zeroized.zeroize();
    assert!(zeroized.seed().iter().all(|byte| *byte == 0));
    assert!(zeroized.secret_key_bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn mldsa_known_answer_vectors_cover_deterministic_api_contracts() {
    assert_eq!(ML_DSA_87_PUBLIC_KEY_SIZE, 2592);
    assert_eq!(ML_DSA_87_SECRET_KEY_SIZE, 4896);
    assert_eq!(ML_DSA_87_SIGNATURE_SIZE, 4627);

    for vector in MLDSA_KAT_VECTORS {
        let seed = decode_hex_array::<32>(vector.seed);
        let message = decode_hex_vec(vector.message);
        let context = decode_hex_vec(vector.context);

        let signer_a = MlDsa87::from_seed(seed);
        let signer_b = MlDsa87::from_seed(seed);
        assert_eq!(signer_a.public_key_bytes(), signer_b.public_key_bytes(), "{}", vector.name);
        assert_eq!(signer_a.secret_key_bytes(), signer_b.secret_key_bytes(), "{}", vector.name);

        let imported = MlDsa87::from_hex_seed(&signer_a.hex_seed()).expect("hex import");
        assert_eq!(imported.public_key_bytes(), signer_a.public_key_bytes(), "{}", vector.name);

        let signature_a = signer_a.sign(&context, &message).expect("signature a");
        let signature_b = signer_a.sign(&context, &message).expect("signature b");
        assert!(
            verify_bytes(&context, &message, &signature_a, &signer_a.public_key_bytes())
                .expect("verify"),
            "{}",
            vector.name
        );
        assert!(
            verify_bytes(&context, &message, &signature_b, &signer_a.public_key_bytes())
                .expect("verify"),
            "{}",
            vector.name
        );

        let mut sealed = signature_a.to_vec();
        sealed.extend_from_slice(&message);
        assert_eq!(
            extract_signature(&sealed).expect("sealed signature").len(),
            ML_DSA_87_SIGNATURE_SIZE,
            "{}",
            vector.name
        );
        assert_eq!(
            extract_message(&sealed).expect("sealed message"),
            message.as_slice(),
            "{}",
            vector.name
        );
        assert_eq!(
            open(&context, &sealed, &signer_a.public_key_bytes()).expect("open").expect("opened"),
            message,
            "{}",
            vector.name
        );

        let wrong_message = if message.is_empty() {
            vec![0x42]
        } else {
            let mut tampered = message.clone();
            tampered[0] ^= 0xff;
            tampered
        };
        assert!(
            !verify_bytes(&context, &wrong_message, &signature_a, &signer_a.public_key_bytes())
                .expect("verify wrong message"),
            "{}",
            vector.name
        );

        if !context.is_empty() {
            let mut wrong_context = context.clone();
            wrong_context[0] ^= 0xff;
            assert!(
                !verify_bytes(&wrong_context, &message, &signature_a, &signer_a.public_key_bytes())
                    .expect("verify wrong context"),
                "{}",
                vector.name
            );
        }
    }

    let seed_a = decode_hex_array::<32>(MLDSA_KAT_VECTORS[0].seed);
    let seed_b = decode_hex_array::<32>(MLDSA_KAT_VECTORS[1].seed);
    let signer_a = MlDsa87::from_seed(seed_a);
    let signer_b = MlDsa87::from_seed(seed_b);
    assert_ne!(signer_a.public_key_bytes(), signer_b.public_key_bytes());
    assert_ne!(signer_a.secret_key_bytes(), signer_b.secret_key_bytes());

    let mut zeroized = MlDsa87::from_seed(seed_a);
    zeroized.zeroize();
    assert!(zeroized.seed().iter().all(|byte| *byte == 0));
    assert!(zeroized.secret_key_bytes().iter().all(|byte| *byte == 0));
}

#[test]
fn sphincs_known_answer_seed_contracts_cover_public_api_regressions() {
    assert_eq!(SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE, 64);
    assert_eq!(SPHINCS_PLUS_256S_SECRET_KEY_SIZE, 128);
    assert_eq!(SPHINCS_PLUS_256S_SIGNATURE_SIZE, 29_792);
    assert_eq!(SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, 96);

    let seed = decode_hex_array::<SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE>(SPHINCS_KAT_SEED);
    let message = decode_hex_vec(SPHINCS_KAT_MESSAGE);

    let signer_a = SphincsPlus256s::from_seed(seed);
    let mut imported = SphincsPlus256s::from_hex_seed(&signer_a.hex_seed()).expect("hex import");
    assert_eq!(imported.public_key_bytes(), signer_a.public_key_bytes());
    assert_eq!(imported.secret_key_bytes(), signer_a.secret_key_bytes());

    let signature = signer_a.sign(&message).expect("signature");
    assert!(verify_sphincsplus_signature(&message, &signature, &signer_a.public_key_bytes()));

    let mut sealed = signature.to_vec();
    sealed.extend_from_slice(&message);
    assert_eq!(sphincsplus_extract_message(&sealed).expect("sealed message"), message.as_slice());
    assert_eq!(
        sphincsplus_extract_signature(&sealed).expect("sealed signature").len(),
        SPHINCS_PLUS_256S_SIGNATURE_SIZE
    );
    assert_eq!(sphincsplus_open(&sealed, &signer_a.public_key_bytes()).expect("opened"), message);

    for short_input in [Vec::new(), vec![0_u8], vec![0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE - 1]] {
        assert!(sphincsplus_open(&short_input, &signer_a.public_key_bytes()).is_none());
        assert!(sphincsplus_extract_message(&short_input).is_none());
        assert!(sphincsplus_extract_signature(&short_input).is_none());
    }

    imported.zeroize();
    assert!(imported.seed().iter().all(|byte| *byte == 0));
    assert!(imported.secret_key_bytes().iter().all(|byte| *byte == 0));
}
