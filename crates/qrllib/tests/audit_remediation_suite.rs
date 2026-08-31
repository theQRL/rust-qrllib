//! Regression suite for the 2026-07 Ciphsure audit remediations:
//! redacting `Debug` on secret-bearing types (CIPH-RUSTQRL-1), the
//! non-echoing seed hex-decode sentinel (CIPH-RUSTQRL-3), the
//! index-preserving XMSS reconstruction constructor (CIPH-RUSTQRL-4), and
//! constant-time seed equality (CIPH-RUSTQRL-9).

use qrllib::{
    Descriptor, ExtendedSeed, LegacyXmssWallet, ML_DSA_87_CRYPTO_SEED_SIZE, MlDsa87, MlDsa87Wallet,
    QrllibError, SEED_SIZE, SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, Seed, SphincsPlus256s,
    XMSS_SECRET_KEY_SIZE, XMSS_SEED_SIZE, Xmss, XmssHashFunction, XmssHeight,
};

/// The recognisable secret byte used to build every fixture below; its decimal
/// rendering (`171`) is what a derived `Debug` would splatter across the output,
/// so asserting the redacted string does not contain it proves no secret array
/// leaked.
const SECRET_BYTE: u8 = 0xAB;
const SECRET_MARK: &str = "171";

// -------------------------------------------------------------------------
// CIPH-RUSTQRL-1 — secret-bearing types must redact their `Debug` output.
// -------------------------------------------------------------------------

#[test]
fn secret_bearing_debug_is_redacted() {
    let seed = Seed::from_bytes(&[SECRET_BYTE; SEED_SIZE]).expect("seed");
    let extended = ExtendedSeed::new(Descriptor::mldsa87(), &seed).expect("extended seed");
    let mldsa = MlDsa87::from_seed([SECRET_BYTE; ML_DSA_87_CRYPTO_SEED_SIZE]);
    let sphincs = SphincsPlus256s::from_seed([SECRET_BYTE; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE]);
    let mldsa_wallet = MlDsa87Wallet::from_seed(seed.clone()).expect("ml-dsa wallet");
    let legacy_wallet =
        LegacyXmssWallet::new(XmssHeight::new(4).expect("height"), XmssHashFunction::Shake256)
            .expect("legacy wallet");
    let xmss = Xmss::initialize_tree(
        XmssHeight::new(4).expect("height"),
        XmssHashFunction::Shake256,
        &[SECRET_BYTE; XMSS_SEED_SIZE],
    )
    .expect("xmss");

    let cases: [(String, &str); 7] = [
        (format!("{seed:?}"), "Seed"),
        (format!("{extended:?}"), "ExtendedSeed"),
        (format!("{mldsa:?}"), "MlDsa87"),
        (format!("{sphincs:?}"), "SphincsPlus256s"),
        (format!("{mldsa_wallet:?}"), "MlDsa87Wallet"),
        (format!("{legacy_wallet:?}"), "LegacyXmssWallet"),
        (format!("{xmss:?}"), "Xmss"),
    ];

    for (rendered, type_name) in cases {
        assert!(rendered.contains(type_name), "debug output should name the type: {rendered}");
        // `finish_non_exhaustive` always emits the `..` elision marker, and a
        // redacted struct stays small. A derived `Debug` that dumped the secret
        // byte arrays would omit `..` and run to tens of thousands of chars.
        // Together these prove redaction even for the wallet fixtures, whose
        // secret keys are KDF-derived and so never contain `SECRET_MARK`
        // literally (the weaker substring check alone would not catch a leak
        // there).
        assert!(rendered.contains(".."), "debug output must elide fields: {rendered}");
        assert!(
            rendered.len() < 512,
            "debug output for {type_name} is too large to be redacted ({} bytes): {rendered}",
            rendered.len()
        );
        assert!(
            !rendered.contains(SECRET_MARK),
            "debug output for {type_name} leaked secret bytes: {rendered}"
        );
    }
}

/// `SphincsPlus256sWallet`'s half of the CIPH-RUSTQRL-1 contract, split out
/// because constructing one needs the gated issuance path. The runtime opt-in
/// helper is compiled only into debug builds or builds with
/// `experimental-sphincsplus-issuance` (TOB-QRLLIB-4 / CIPH-RUSTQRL-6), and
/// integration tests do not inherit the crate's own `cfg(test)` scope, so this
/// test carries the same cfg and `cargo test --release` still compiles without
/// the feature. Default `cargo test` and `cargo llvm-cov` are debug builds and
/// run it as before.
#[cfg(any(debug_assertions, feature = "experimental-sphincsplus-issuance"))]
#[test]
fn sphincs_wallet_debug_is_redacted() {
    qrllib::enable_experimental_sphincsplus_issuance_for_testing();

    let seed = Seed::from_bytes(&[SECRET_BYTE; SEED_SIZE]).expect("seed");
    let wallet = qrllib::SphincsPlus256sWallet::from_seed(seed).expect("sphincs wallet");
    let rendered = format!("{wallet:?}");

    assert!(rendered.contains("SphincsPlus256sWallet"), "debug output should name the type");
    assert!(rendered.contains(".."), "debug output must elide fields: {rendered}");
    assert!(
        rendered.len() < 512,
        "debug output is too large to be redacted ({} bytes): {rendered}",
        rendered.len()
    );
    assert!(!rendered.contains(SECRET_MARK), "debug output leaked secret bytes: {rendered}");
}

// -------------------------------------------------------------------------
// CIPH-RUSTQRL-3 — seed hex-decode errors must not echo the input bytes.
// -------------------------------------------------------------------------

#[test]
fn seed_from_hex_uses_non_echoing_sentinel() {
    // 'z' is not a hex digit; the raw `hex` error would echo it and its offset.
    let seed_err = Seed::from_hex("zz").expect_err("invalid hex must fail");
    assert!(matches!(seed_err, QrllibError::InvalidHexSeed));
    assert_eq!(seed_err.to_string(), "invalid hex seed");
    assert!(!seed_err.to_string().contains('z'));

    let extended_err = ExtendedSeed::from_hex("0xzz").expect_err("invalid hex must fail");
    assert!(matches!(extended_err, QrllibError::InvalidHexSeed));
    assert_eq!(extended_err.to_string(), "invalid hex seed");
}

// -------------------------------------------------------------------------
// CIPH-RUSTQRL-4 — reconstruct an XMSS signer preserving the OTS index.
// -------------------------------------------------------------------------

#[test]
fn xmss_from_secret_key_preserves_index() {
    let height = XmssHeight::new(4).expect("height");
    let mut signer =
        Xmss::initialize_tree(height, XmssHashFunction::Shake256, &[9_u8; XMSS_SEED_SIZE])
            .expect("xmss");

    // Advance the OTS index by signing a few times.
    signer.sign(b"m0").expect("sign 0");
    signer.sign(b"m1").expect("sign 1");
    let high_water = signer.index();
    assert_eq!(high_water, 2);

    let persisted = signer.secret_key();
    let public_key = signer.public_key();

    // Reconstruct from the persisted secret key: same public key, resumed index.
    let mut resumed =
        Xmss::from_secret_key(height, XmssHashFunction::Shake256, &persisted).expect("reconstruct");
    assert_eq!(resumed.index(), high_water, "index must be restored, not reset to 0");
    assert_eq!(resumed.public_key(), public_key, "reconstruction must reproduce the tree");

    // The next signature uses the resumed index (no reuse of spent leaves).
    let signature = resumed.sign(b"m2").expect("sign after resume");
    assert_eq!(resumed.index(), high_water + 1);
    assert!(qrllib::verify_xmss(
        XmssHashFunction::Shake256,
        b"m2",
        &signature,
        &resumed.public_key(),
    ));
}

#[test]
fn xmss_from_secret_key_rejects_wrong_length() {
    let height = XmssHeight::new(4).expect("height");
    let err = Xmss::from_secret_key(height, XmssHashFunction::Shake256, &[0_u8; 8])
        .expect_err("short secret key must be rejected");
    assert!(matches!(err, QrllibError::InvalidXmssKeyLength(8)));
}

#[test]
fn xmss_from_secret_key_rejects_out_of_range_index() {
    let height = XmssHeight::new(4).expect("height");
    let signer = Xmss::initialize_tree(height, XmssHashFunction::Shake256, &[5_u8; XMSS_SEED_SIZE])
        .expect("xmss");

    // Craft a secret key whose encoded index is far beyond the tree capacity
    // (2^4 = 16). `set_index` inside the reconstruction must reject it rather
    // than walking an unbounded BDS chain.
    let mut crafted = signer.secret_key().to_vec();
    crafted[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(crafted.len(), XMSS_SECRET_KEY_SIZE);

    let err = Xmss::from_secret_key(height, XmssHashFunction::Shake256, &crafted)
        .expect_err("out-of-range index must be rejected");
    assert!(matches!(err, QrllibError::XmssOtsIndexTooHigh));
}

// -------------------------------------------------------------------------
// CIPH-RUSTQRL-9 — seed equality is content-based and constant-time.
// -------------------------------------------------------------------------

#[test]
fn seed_equality_covers_equal_and_unequal() {
    let a = Seed::from_bytes(&[1_u8; SEED_SIZE]).expect("seed a");
    let a_again = Seed::from_bytes(&[1_u8; SEED_SIZE]).expect("seed a'");
    let mut differing = [1_u8; SEED_SIZE];
    differing[SEED_SIZE - 1] = 2; // differs only in the final byte
    let b = Seed::from_bytes(&differing).expect("seed b");

    assert_eq!(a, a_again);
    assert_ne!(a, b);

    let ext_a = ExtendedSeed::new(Descriptor::mldsa87(), &a).expect("ext a");
    let ext_b = ExtendedSeed::new(Descriptor::mldsa87(), &b).expect("ext b");
    assert_ne!(ext_a, ext_b);
}
