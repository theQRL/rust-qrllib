//! NIST ACVP ML-DSA-87 keyGen / sigGen conformance tests (FIPS 204).
//!
//! Reads the merged vector files produced by `.github/acvp/merge_vectors.py`
//! (`keygen.json`, `siggen.json`) from the directory named by the
//! `ACVP_VECTORS_DIR` environment variable; when it is unset the tests log a
//! skip notice and pass. Lives in-crate alongside the Wycheproof harness so
//! the two FIPS 204 conformance suites share one location and one convention:
//! the primitive is exercised as the standard specifies, and key validation
//! is checked separately (here, that every NIST-generated public key passes
//! [`super::validate_mldsa_public_key`]). See `.github/acvp/README.md`.

use std::{env, fs, path::PathBuf};

use super::{
    ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    PublicKey, sign_with_secret_key_deterministic,
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
    // Coverage: the coverage run always sets ACVP_VECTORS_DIR, so the skip
    // arm (for environments without the NIST vectors) is never taken here.
    let Some(vectors_dir) = acvp_vectors_dir() else {
        //coverage:ignore start reason=defensively-unreachable
        eprintln!("ACVP_VECTORS_DIR not set; skipping ML-DSA ACVP keygen test");
        return;
        //coverage:ignore end
    };

    let data = fs::read_to_string(vectors_dir.join("keygen.json")).expect("read keygen.json");
    let vectors: Vec<AcvpKeyGenVector> = serde_json::from_str(&data).expect("parse keygen.json");
    assert!(!vectors.is_empty(), "no ACVP keygen vectors found");
    eprintln!("Running ACVP ML-DSA-87 keyGen: {} vectors", vectors.len());

    for vector in vectors {
        let seed_bytes = hex::decode(&vector.seed).expect("seed hex");
        assert_eq!(seed_bytes.len(), 32, "tc{}", vector.tc_id);
        let expected_pk = hex::decode(&vector.pk).expect("public key hex");
        let expected_sk = hex::decode(&vector.sk).expect("secret key hex");

        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let signer = MlDsa87::from_seed(seed)
            .unwrap_or_else(|e| panic!("tc{}: key generation failed: {}", vector.tc_id, e));

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
        // Validation must never reject a NIST-generated key: an honest key
        // has about 1280 large t1 coefficients against the 76 the weak-key
        // rule requires.
        let public_key = PublicKey::from_bytes(&expected_pk)
            .unwrap_or_else(|e| panic!("tc{}: NIST public key rejected: {}", vector.tc_id, e));
        assert_eq!(public_key, signer.public_key(), "tc{}", vector.tc_id);
    }
}

#[test]
fn acvp_siggen_matches_nist_vectors() {
    // Coverage: the coverage run always sets ACVP_VECTORS_DIR, so the skip
    // arm (for environments without the NIST vectors) is never taken here.
    let Some(vectors_dir) = acvp_vectors_dir() else {
        //coverage:ignore start reason=defensively-unreachable
        eprintln!("ACVP_VECTORS_DIR not set; skipping ML-DSA ACVP siggen test");
        return;
        //coverage:ignore end
    };

    let data = fs::read_to_string(vectors_dir.join("siggen.json")).expect("read siggen.json");
    let vectors: Vec<AcvpSigGenVector> = serde_json::from_str(&data).expect("parse siggen.json");
    assert!(!vectors.is_empty(), "no ACVP siggen vectors found");
    eprintln!("Running ACVP ML-DSA-87 sigGen: {} vectors", vectors.len());

    for vector in vectors {
        let secret_key = hex::decode(&vector.sk).expect("secret key hex");
        let message = hex::decode(&vector.message).expect("message hex");
        let context = hex::decode(&vector.context).expect("context hex");
        let expected_signature = hex::decode(&vector.signature).expect("signature hex");

        assert_eq!(secret_key.len(), ML_DSA_87_SECRET_KEY_SIZE, "tc{}", vector.tc_id);
        assert_eq!(expected_signature.len(), ML_DSA_87_SIGNATURE_SIZE, "tc{}", vector.tc_id);

        let mut secret_key_bytes = [0_u8; ML_DSA_87_SECRET_KEY_SIZE];
        secret_key_bytes.copy_from_slice(&secret_key);
        // ACVP siggen vectors are pinned to FIPS 204 §3.5 deterministic
        // mode (`rnd = 32 zero bytes`). The public `sign` API is hedged
        // by default per TOB-QRLLIB-6, so route through the explicit
        // `sign_with_secret_key_deterministic` entry point to reproduce
        // the vectors byte-for-byte.
        let signature = sign_with_secret_key_deterministic(&context, &message, &secret_key_bytes)
            .expect("ACVP signature generation should succeed");

        assert_eq!(signature.len(), ML_DSA_87_SIGNATURE_SIZE);
        assert_eq!(signature.as_slice(), expected_signature.as_slice(), "tc{}", vector.tc_id);
    }
}
