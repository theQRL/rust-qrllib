use std::{env, fs, path::PathBuf};

use qrllib::{
    ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    mldsa::sign_with_secret_key,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpKeyGenVector {
    tc_id: u32,
    seed: String,
    pk: String,
    sk: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpSigGenVector {
    tc_id: u32,
    sk: String,
    message: String,
    context: String,
    signature: String,
}

fn acvp_vectors_dir() -> Option<PathBuf> {
    env::var_os("ACVP_VECTORS_DIR").map(PathBuf::from)
}

#[test]
fn acvp_keygen_matches_nist_vectors() {
    let Some(vectors_dir) = acvp_vectors_dir() else {
        eprintln!("ACVP_VECTORS_DIR not set; skipping ML-DSA ACVP keygen test");
        return;
    };

    let data = fs::read_to_string(vectors_dir.join("keygen.json")).expect("read keygen.json");
    let vectors: Vec<AcvpKeyGenVector> = serde_json::from_str(&data).expect("parse keygen.json");
    assert!(!vectors.is_empty(), "no ACVP keygen vectors found");

    for vector in vectors {
        let seed_bytes = hex::decode(&vector.seed).expect("seed hex");
        assert_eq!(seed_bytes.len(), 32, "tc{}", vector.tc_id);
        let expected_pk = hex::decode(&vector.pk).expect("public key hex");
        let expected_sk = hex::decode(&vector.sk).expect("secret key hex");

        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let signer = MlDsa87::from_seed(seed);

        assert_eq!(signer.public_key_bytes().len(), ML_DSA_87_PUBLIC_KEY_SIZE);
        assert_eq!(signer.secret_key_bytes().len(), ML_DSA_87_SECRET_KEY_SIZE);
        assert_eq!(
            signer.public_key_bytes().as_slice(),
            expected_pk.as_slice(),
            "tc{}",
            vector.tc_id
        );
        assert_eq!(
            signer.secret_key_bytes().as_slice(),
            expected_sk.as_slice(),
            "tc{}",
            vector.tc_id
        );
    }
}

#[test]
fn acvp_siggen_matches_nist_vectors() {
    let Some(vectors_dir) = acvp_vectors_dir() else {
        eprintln!("ACVP_VECTORS_DIR not set; skipping ML-DSA ACVP siggen test");
        return;
    };

    let data = fs::read_to_string(vectors_dir.join("siggen.json")).expect("read siggen.json");
    let vectors: Vec<AcvpSigGenVector> = serde_json::from_str(&data).expect("parse siggen.json");
    assert!(!vectors.is_empty(), "no ACVP siggen vectors found");

    for vector in vectors {
        let secret_key = hex::decode(&vector.sk).expect("secret key hex");
        let message = hex::decode(&vector.message).expect("message hex");
        let context = hex::decode(&vector.context).expect("context hex");
        let expected_signature = hex::decode(&vector.signature).expect("signature hex");

        assert_eq!(secret_key.len(), ML_DSA_87_SECRET_KEY_SIZE, "tc{}", vector.tc_id);
        assert_eq!(expected_signature.len(), ML_DSA_87_SIGNATURE_SIZE, "tc{}", vector.tc_id);

        let mut secret_key_bytes = [0_u8; ML_DSA_87_SECRET_KEY_SIZE];
        secret_key_bytes.copy_from_slice(&secret_key);
        let signature = sign_with_secret_key(&context, &message, &secret_key_bytes)
            .expect("ACVP signature generation should succeed");

        assert_eq!(signature.len(), ML_DSA_87_SIGNATURE_SIZE);
        assert_eq!(signature.as_slice(), expected_signature.as_slice(), "tc{}", vector.tc_id);
    }
}
