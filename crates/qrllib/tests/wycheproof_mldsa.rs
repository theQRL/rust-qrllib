//! Wycheproof ML-DSA-87 verifier consistency tests, ported from the
//! `go-qrllib` Wycheproof integration. Exercises the C2SP/wycheproof
//! `mldsa_87_verify_test.json` corpus against [`MlDsa87::verify`] /
//! [`verify_bytes`]: every test vector specifies an expected outcome
//! (`valid` / `invalid` / `acceptable`); this runner asserts the
//! library's verify result matches.
//!
//! The vector corpus is **not** vendored — the CI workflow clones
//! `https://github.com/C2SP/wycheproof` sparsely at run time and points
//! at `testvectors_v1/` via the `WYCHEPROOF_VECTORS_DIR` environment
//! variable (see `.github/workflows/wycheproof.yml`). When the env var
//! is unset the test logs a skip notice and exits successfully so
//! day-to-day `cargo test` doesn't require the vectors to be present.

use std::{env, fs, path::PathBuf};

use qrllib::{
    ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, mldsa::verify_bytes,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct WycheproofVerifyFile {
    algorithm: String,
    #[serde(rename = "numberOfTests")]
    number_of_tests: u32,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "type")]
    group_type: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    tests: Vec<TestVector>,
}

#[derive(Deserialize)]
struct TestVector {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(default)]
    comment: String,
    msg: String,
    #[serde(default)]
    ctx: String,
    sig: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

fn wycheproof_vectors_dir() -> Option<PathBuf> {
    env::var_os("WYCHEPROOF_VECTORS_DIR").map(PathBuf::from)
}

#[test]
fn wycheproof_mldsa87_verify_matches_expected_outcomes() {
    let Some(vectors_dir) = wycheproof_vectors_dir() else {
        eprintln!("WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof ML-DSA-87 verify tests");
        return;
    };

    let path = vectors_dir.join("mldsa_87_verify_test.json");
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let file: WycheproofVerifyFile = serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));

    assert_eq!(file.algorithm, "ML-DSA-87", "unexpected algorithm in vector file");
    assert!(!file.test_groups.is_empty(), "no test groups in vector file");

    let mut total_pass = 0u32;
    let mut total_acceptable = 0u32;

    eprintln!(
        "Running Wycheproof ML-DSA-87 Verify: {} groups, {} total tests",
        file.test_groups.len(),
        file.number_of_tests
    );

    for (gi, group) in file.test_groups.iter().enumerate() {
        if group.group_type != "MlDsaVerify" {
            eprintln!("group {}: skipping unrecognised type {:?}", gi, group.group_type);
            continue;
        }

        let pk_bytes = hex::decode(&group.public_key)
            .unwrap_or_else(|e| panic!("group {}: invalid publicKey hex: {}", gi, e));

        // Wycheproof occasionally includes malformed-pk groups to test
        // that verifiers reject them. If the pk length doesn't match
        // ML-DSA-87, every test in the group should expect "invalid".
        let pk_length_ok = pk_bytes.len() == ML_DSA_87_PUBLIC_KEY_SIZE;

        for tc in &group.tests {
            let msg = hex::decode(&tc.msg).unwrap_or_else(|e| {
                panic!("g{}_tc{}: invalid msg hex: {}", gi, tc.tc_id, e)
            });
            let sig = hex::decode(&tc.sig).unwrap_or_else(|e| {
                panic!("g{}_tc{}: invalid sig hex: {}", gi, tc.tc_id, e)
            });
            let ctx = hex::decode(&tc.ctx).unwrap_or_else(|e| {
                panic!("g{}_tc{}: invalid ctx hex: {}", gi, tc.tc_id, e)
            });

            // Mirror go-qrllib: wrong-length pk or sig is rejected at
            // the API boundary, which is also what `verify_bytes`
            // expresses (length mismatches return `Err` or `Ok(false)`).
            let ok = if !pk_length_ok || sig.len() != ML_DSA_87_SIGNATURE_SIZE {
                false
            } else {
                verify_bytes(&ctx, &msg, &sig, &pk_bytes).unwrap_or(false)
            };

            match tc.result.as_str() {
                "valid" => {
                    if !ok {
                        panic!(
                            "g{}_tc{}: expected valid; verify returned false. comment={:?} flags={:?}",
                            gi, tc.tc_id, tc.comment, tc.flags
                        );
                    }
                    total_pass += 1;
                }
                "invalid" => {
                    if ok {
                        panic!(
                            "g{}_tc{}: expected invalid; verify returned true. comment={:?} flags={:?}",
                            gi, tc.tc_id, tc.comment, tc.flags
                        );
                    }
                    total_pass += 1;
                }
                "acceptable" => {
                    // Spec allows either outcome — record but don't fail.
                    total_acceptable += 1;
                    eprintln!(
                        "g{}_tc{}: acceptable (observed={}), comment={:?} flags={:?}",
                        gi, tc.tc_id, ok, tc.comment, tc.flags
                    );
                }
                other => {
                    panic!("g{}_tc{}: unknown result {:?}", gi, tc.tc_id, other);
                }
            }
        }
    }

    eprintln!(
        "Wycheproof ML-DSA-87 Verify summary: pass={} acceptable={}",
        total_pass, total_acceptable
    );
}
