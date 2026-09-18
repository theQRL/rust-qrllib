//! C2SP/wycheproof ML-DSA-87 verifier consistency tests, ported from the
//! `go-qrllib` Wycheproof integration. Walks `mldsa_87_verify_test.json`:
//! every vector specifies an expected outcome (`valid` / `invalid` /
//! `acceptable`) and this runner asserts the library's verify result matches.
//!
//! This is a conformance harness for the FIPS 204 Algorithm 8 primitive, so it
//! lives in-crate: it must exercise `verify_bytes` on arbitrary keys,
//! including the weak keys of the `ZeroPublicKey` groups (all-zero t1; tcId
//! 66 and 174 are `valid` and must verify) and of the `MissingReduction`
//! group (every t1 coefficient 1023; tcId 240 is `valid` and must verify),
//! which the public [`PublicKey::from_bytes`] rightly rejects. The
//! `#[cfg(test)]`-only [`PublicKey::from_bytes_unchecked`] is the only way
//! past key validation, and it is not reachable from downstream crates. The
//! harness also checks the split itself: exactly those groups' keys are
//! rejected as weak, and every other well-formed key in the corpus passes
//! [`super::validate_mldsa_public_key`].
//!
//! The vector corpus is **not** vendored, the CI workflow clones
//! `https://github.com/C2SP/wycheproof` sparsely at run time and points at
//! `testvectors_v1/` via the `WYCHEPROOF_VECTORS_DIR` environment variable
//! (see `.github/workflows/wycheproof.yml`). When the env var is unset the
//! test logs a skip notice and exits successfully so day-to-day `cargo test`
//! doesn't require the vectors to be present.

use std::{env, fs, path::PathBuf};

use super::{
    ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, PublicKey, validate_mldsa_public_key,
    verify_bytes,
};
use crate::QrllibError;
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

/// Upstream attaches key-shape flags to the tests of a group rather than to
/// the group; a group carries the flag if any of its tests does.
fn group_has_flag(group: &TestGroup, flag: &str) -> bool {
    group.tests.iter().any(|tc| tc.flags.iter().any(|f| f == flag))
}

#[test]
fn wycheproof_mldsa87_verify_matches_expected_outcomes() {
    // Coverage: the coverage run always sets WYCHEPROOF_VECTORS_DIR, so the
    // skip arm (for environments without the upstream vectors) is never taken
    // here.
    let Some(vectors_dir) = wycheproof_vectors_dir() else {
        //coverage:ignore start reason=defensively-unreachable
        eprintln!("WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof ML-DSA-87 verify tests");
        return;
        //coverage:ignore end
    };

    let path = vectors_dir.join("mldsa_87_verify_test.json");
    let data =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let file: WycheproofVerifyFile =
        serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));

    assert_eq!(file.algorithm, "ML-DSA-87", "unexpected algorithm in vector file");
    assert!(!file.test_groups.is_empty(), "no test groups in vector file");

    let mut total_pass = 0u32;
    let mut total_acceptable = 0u32;
    // Vectors run under a weak key (the all-zero `ZeroPublicKey` groups and
    // the all-1023 `MissingReduction` group): key validation rejects those
    // keys, but the primitive must still produce the upstream-expected
    // result.
    let mut weak_key_vectors = 0u32;
    let mut weak_key_valid_accepted = Vec::new();
    let mut zero_public_key_valid_accepted = 0u32;
    let mut missing_reduction_valid_accepted = 0u32;

    eprintln!(
        "Running Wycheproof ML-DSA-87 Verify: {} groups, {} total tests",
        file.test_groups.len(),
        file.number_of_tests
    );

    for (gi, group) in file.test_groups.iter().enumerate() {
        // Coverage: every group in the upstream corpus is `MlDsaVerify`; the
        // arm is retained so a future group type is reported rather than
        // silently run as a verify group.
        if group.group_type != "MlDsaVerify" {
            //coverage:ignore start reason=defensively-unreachable
            eprintln!("group {}: skipping unrecognised type {:?}", gi, group.group_type);
            continue;
            //coverage:ignore end
        }

        let pk_bytes = hex::decode(&group.public_key)
            .unwrap_or_else(|e| panic!("group {}: invalid publicKey hex: {}", gi, e));

        // Wycheproof includes malformed-pk groups to test that verifiers
        // reject them. A wrong-length pk cannot be wrapped even unchecked (the
        // array type enforces the length), so every test in such a group must
        // expect "invalid", mirroring the API-boundary rejection go-qrllib
        // applies.
        let public_key = (pk_bytes.len() == ML_DSA_87_PUBLIC_KEY_SIZE).then(|| {
            let mut packed = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
            packed.copy_from_slice(&pk_bytes);
            PublicKey::from_bytes_unchecked(packed)
        });

        // Key validation must reject exactly the weak-key groups: upstream
        // flags them `ZeroPublicKey` (all-zero t1) and `MissingReduction`
        // (every t1 coefficient 1023, so 2^13·t1 = q - 1). Every other
        // well-formed key in the corpus is honestly generated and must pass.
        let zero_public_key_group = group_has_flag(group, "ZeroPublicKey");
        let missing_reduction_group = group_has_flag(group, "MissingReduction");
        let weak_key = public_key.is_some() && (zero_public_key_group || missing_reduction_group);
        if public_key.is_some() {
            let verdict = validate_mldsa_public_key(&pk_bytes);
            if weak_key {
                assert!(
                    matches!(verdict, Err(QrllibError::WeakPublicKey)),
                    "group {gi}: expected the weak-key group to be rejected, got {verdict:?}"
                );
            } else {
                verdict.unwrap_or_else(|e| panic!("group {gi}: honest key rejected: {e}"));
            }
        }

        for tc in &group.tests {
            let msg = hex::decode(&tc.msg)
                .unwrap_or_else(|e| panic!("g{}_tc{}: invalid msg hex: {}", gi, tc.tc_id, e));
            let sig = hex::decode(&tc.sig)
                .unwrap_or_else(|e| panic!("g{}_tc{}: invalid sig hex: {}", gi, tc.tc_id, e));
            let ctx = hex::decode(&tc.ctx)
                .unwrap_or_else(|e| panic!("g{}_tc{}: invalid ctx hex: {}", gi, tc.tc_id, e));

            // Wrong-length sig is rejected at the API boundary (`verify_bytes`
            // returns `Err`, mapped to `false` here).
            let ok = match &public_key {
                Some(key) if sig.len() == ML_DSA_87_SIGNATURE_SIZE => {
                    verify_bytes(&ctx, &msg, &sig, key).unwrap_or(false)
                }
                _ => false,
            };
            if weak_key {
                weak_key_vectors += 1;
            }

            match tc.result.as_str() {
                "valid" => {
                    assert!(
                        ok,
                        "g{}_tc{}: expected valid; verify returned false. comment={:?} flags={:?}",
                        gi, tc.tc_id, tc.comment, tc.flags
                    );
                    if weak_key {
                        weak_key_valid_accepted.push(tc.tc_id);
                        zero_public_key_valid_accepted += u32::from(zero_public_key_group);
                        missing_reduction_valid_accepted += u32::from(missing_reduction_group);
                    }
                    total_pass += 1;
                }
                "invalid" => {
                    assert!(
                        !ok,
                        "g{}_tc{}: expected invalid; verify returned true. comment={:?} flags={:?}",
                        gi, tc.tc_id, tc.comment, tc.flags
                    );
                    total_pass += 1;
                }
                // Coverage: the Wycheproof schema permits `acceptable` (either
                // outcome allowed) but the upstream ML-DSA-87 corpus currently
                // has none (71 valid / 170 invalid); the arm is retained so a
                // future acceptable vector is recorded rather than failing as
                // an unknown result. Any other value is a schema violation.
                //coverage:ignore start reason=defensively-unreachable
                "acceptable" => {
                    total_acceptable += 1;
                    eprintln!(
                        "g{}_tc{}: acceptable (observed={}), comment={:?} flags={:?}",
                        gi, tc.tc_id, ok, tc.comment, tc.flags
                    );
                }
                other => panic!("g{}_tc{}: unknown result {:?}", gi, tc.tc_id, other),
                //coverage:ignore end
            }
        }
    }

    eprintln!(
        "Wycheproof ML-DSA-87 Verify summary: pass={} acceptable={} weak_key_vectors={} weak_key_valid_accepted={:?}",
        total_pass, total_acceptable, weak_key_vectors, weak_key_valid_accepted
    );
    assert_eq!(
        total_pass + total_acceptable,
        file.number_of_tests,
        "every vector in the file must have been exercised"
    );
    // FIPS 204 conformance pin: the primitive accepted at least one upstream
    // `valid` signature under each weak key (tcId 66 / 174 for the all-zero
    // key and tcId 240 for the all-1023 key upstream). If this ever fails,
    // key validation has leaked into the verify primitive.
    assert!(
        zero_public_key_valid_accepted > 0,
        "expected the ZeroPublicKey `valid` vectors (tcId 66 / 174 upstream) to verify"
    );
    assert!(
        missing_reduction_valid_accepted > 0,
        "expected the MissingReduction `valid` vector (tcId 240 upstream) to verify"
    );
}
