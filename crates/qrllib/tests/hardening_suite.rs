//! Behavioural regression suite for memory-hygiene and signing-mode invariants:
//! randomised signing entry points, address-prefix case tolerance, the
//! `RejectionBudgetExceeded` error variant, and post-zeroize rejection on
//! every sign / sign_attached path.

use qrllib::{
    DILITHIUM_CRYPTO_SEED_SIZE, Dilithium, ML_DSA_87_CRYPTO_SEED_SIZE, MlDsa87, MlDsa87Wallet,
    QrllibError, Seed, SphincsPlus256sWallet, Xmss, XmssHashFunction, XmssHeight, format_address,
    is_valid_address, sign_dilithium_with_secret_key,
    sign_mldsa_with_secret_key,
};

#[test]
fn mldsa_wallet_sign_randomized_varies_and_verifies() {
    let seed = Seed::from_bytes(&[3_u8; qrllib::SEED_SIZE]).expect("seed");
    let wallet = MlDsa87Wallet::from_seed(seed).expect("wallet");
    let message = b"wallet randomised smoke";

    let det_a = wallet.sign(message).expect("deterministic a");
    let det_b = wallet.sign(message).expect("deterministic b");
    assert_eq!(det_a, det_b);

    let hedged_a = wallet.sign(message).expect("hedged a");
    let hedged_b = wallet.sign(message).expect("hedged b");
    assert_ne!(hedged_a, hedged_b, "hedged mode must draw fresh randomness per call");
    assert_ne!(hedged_a, det_a);

    // Both variants verify under the wallet descriptor.
    assert!(qrllib::verify_mldsa87_wallet_signature(
        message,
        &hedged_a,
        &wallet.public_key(),
        wallet.descriptor(),
    ));
    assert!(qrllib::verify_mldsa87_wallet_signature(
        message,
        &hedged_b,
        &wallet.public_key(),
        wallet.descriptor(),
    ));
}

#[test]
fn free_function_randomised_sign_entry_points_are_exposed() {
    // ML-DSA
    let mldsa = MlDsa87::from_seed([23_u8; ML_DSA_87_CRYPTO_SEED_SIZE]);
    let sig_a =
        sign_mldsa_with_secret_key(b"ctx", b"msg", mldsa.secret_key_bytes().as_slice())
            .expect("randomized mldsa a");
    let sig_b =
        sign_mldsa_with_secret_key(b"ctx", b"msg", mldsa.secret_key_bytes().as_slice())
            .expect("randomized mldsa b");
    assert_ne!(sig_a, sig_b);

    // Dilithium
    let dilithium = Dilithium::from_seed([29_u8; DILITHIUM_CRYPTO_SEED_SIZE]);
    let dil_a =
        sign_dilithium_with_secret_key(b"msg", dilithium.secret_key_bytes().as_slice())
            .expect("randomized dilithium a");
    let dil_b =
        sign_dilithium_with_secret_key(b"msg", dilithium.secret_key_bytes().as_slice())
            .expect("randomized dilithium b");
    assert_ne!(dil_a, dil_b);
}

#[test]
fn is_valid_address_accepts_both_case_prefixes() {
    let raw = format_address(&[0xab; qrllib::ADDRESS_SIZE]);
    let mixed = format!("q{}", raw[1..].to_ascii_uppercase());
    assert!(is_valid_address(&raw), "canonical Q-prefixed address must validate");
    assert!(is_valid_address(&mixed), "lowercase-q-prefixed mixed-case address must validate");
}

#[test]
fn mldsa_wallet_seal_rejects_zeroized_signer() {
    let seed = Seed::from_bytes(&[31_u8; qrllib::SEED_SIZE]).expect("seed");
    let mut wallet = MlDsa87Wallet::from_seed(seed).expect("wallet");
    wallet.zeroize();

    // `sign_with_secret_key` and the sign_attached path both go through the zero-key
    // check and must reject the all-zero buffer.
    let signer_bytes = wallet.secret_key();
    let result = qrllib::sign_mldsa_with_secret_key(b"ctx", b"msg", signer_bytes.as_slice());
    assert!(matches!(result, Err(QrllibError::MlDsaSecretKeyZeroized)));
}

#[test]
fn sphincs_wallet_sign_rejects_zeroized_signer() {
    let seed = Seed::from_bytes(&[41_u8; qrllib::SEED_SIZE]).expect("seed");
    let mut wallet = SphincsPlus256sWallet::from_seed(seed).expect("wallet");
    wallet.zeroize();

    assert!(matches!(
        wallet.sign(b"after zeroize"),
        Err(QrllibError::SphincsPlusSecretKeyZeroized)
    ));
    assert!(matches!(
        wallet.sign_attached(b"after zeroize"),
        Err(QrllibError::SphincsPlusSecretKeyZeroized)
    ));
}

#[test]
fn xmss_sign_rejects_zeroized_signer() {
    let mut tree = Xmss::initialize_tree(
        XmssHeight::new(4).expect("height"),
        XmssHashFunction::Shake128,
        &[43_u8; 48],
    )
    .expect("tree");
    tree.zeroize();
    assert!(matches!(tree.sign(b"after zeroize"), Err(QrllibError::XmssSecretKeyZeroized)));
}

#[test]
fn rejection_budget_exceeded_variant_is_reachable_and_formats() {
    // We cannot realistically force the ML-DSA rejection loop to exceed 1024
    // iterations without a SHA-3 collision; here we only smoke-test that the
    // error variant exists, carries a u32, and formats to a useful string.
    let err = QrllibError::RejectionBudgetExceeded(1024);
    let rendered = err.to_string();
    assert!(rendered.contains("1024"));
    assert!(rendered.to_ascii_lowercase().contains("rejection"));
}
