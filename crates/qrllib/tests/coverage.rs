use qrllib::{
    ADDRESS_SIZE, DESCRIPTOR_SIZE, Descriptor, ExtendedSeed, ML_DSA_87_CRYPTO_SEED_SIZE,
    ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    MlDsa87Wallet, QrllibError, SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE, Seed,
    SphincsPlus256s, WalletType, bin_to_mnemonic, extract_message, extract_signature,
    format_address, get_address, is_valid_address, mnemonic_to_bin, open,
    validate_mldsa_public_key, validate_mldsa_secret_key, verify_mldsa87_wallet_signature,
};

#[test]
fn descriptor_wallet_type_and_address_validation_paths_are_exercised() {
    let descriptor = Descriptor::mldsa87();
    assert_eq!(descriptor.type_code(), WalletType::MlDsa87.code());
    assert_eq!(descriptor.metadata(), [0, 0]);
    assert_eq!(descriptor.to_bytes().len(), DESCRIPTOR_SIZE);
    assert_eq!(descriptor.wallet_type().expect("wallet type"), WalletType::MlDsa87);

    let invalid_descriptor = Descriptor::new([9, 0, 0]);
    assert!(!invalid_descriptor.is_valid());
    assert!(invalid_descriptor.validate().is_err());
    assert!(Descriptor::from_bytes(&[1, 2]).is_err());

    for nonzero_metadata in [
        [WalletType::MlDsa87.code(), 0x01, 0x00],
        [WalletType::MlDsa87.code(), 0x00, 0x01],
        [WalletType::MlDsa87.code(), 0xff, 0xff],
        [WalletType::SphincsPlus256s.code(), 0x01, 0x00],
        [WalletType::SphincsPlus256s.code(), 0x00, 0x01],
        [WalletType::SphincsPlus256s.code(), 0xff, 0xff],
    ] {
        let descriptor = Descriptor::new(nonzero_metadata);
        assert!(
            !descriptor.is_valid(),
            "descriptor with non-zero metadata bytes must be rejected: {nonzero_metadata:?}"
        );
        assert!(descriptor.validate().is_err());
        assert!(
            ExtendedSeed::new(descriptor, &Seed::from_bytes(&[0_u8; SEED_SIZE]).unwrap()).is_err()
        );
        assert!(get_address(&[0_u8; ML_DSA_87_PUBLIC_KEY_SIZE], descriptor).is_err());
    }
    // Descriptor-level gates, parity with go-qrllib's `descriptor.IsValid` /
    // `IsIssuable` / `IsVerifiable` (TOB-QRLLIB-4). ML-DSA-87 passes all
    // three; the reserved SPHINCS+ descriptor passes none, and neither does
    // an unknown type code.
    assert!(descriptor.is_valid() && descriptor.is_issuable() && descriptor.is_verifiable());
    let sphincs_descriptor = Descriptor::sphincsplus256s();
    assert!(!sphincs_descriptor.is_valid());
    assert!(!sphincs_descriptor.is_issuable());
    assert!(!sphincs_descriptor.is_verifiable());
    assert!(sphincs_descriptor.validate().is_err());
    assert!(!invalid_descriptor.is_issuable());
    assert!(!invalid_descriptor.is_verifiable());
    assert!(
        get_address(&[0_u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE], sphincs_descriptor).is_err(),
        "SPHINCS+ descriptor must not derive a common address"
    );

    assert!(matches!(WalletType::try_from(0), Err(QrllibError::UnknownWalletType(0))));
    assert!(matches!(WalletType::try_from(9), Err(QrllibError::UnknownWalletType(9))));
    assert!(WalletType::MlDsa87.is_valid());
    assert!(!WalletType::SphincsPlus256s.is_valid());
    assert_eq!(WalletType::MlDsa87.expected_public_key_size(), ML_DSA_87_PUBLIC_KEY_SIZE);
    assert_eq!(WalletType::SphincsPlus256s.expected_public_key_size(), 64);
    assert_eq!(WalletType::MlDsa87.to_string(), "ML_DSA_87");
    assert_eq!(WalletType::SphincsPlus256s.to_string(), "SPHINCSPLUS_256S");

    let signer = MlDsa87::from_seed([7_u8; ML_DSA_87_CRYPTO_SEED_SIZE]);
    let address = get_address(&signer.public_key_bytes(), descriptor).expect("address");
    assert_eq!(address.len(), ADDRESS_SIZE);
    let address_string = format_address(&address);
    assert!(is_valid_address(&address_string));
    assert!(!is_valid_address("Qdeadbeef"));
    assert!(get_address(&[0_u8; 1], descriptor).is_err());
    assert!(get_address(&signer.public_key_bytes(), invalid_descriptor).is_err());
}

#[test]
fn seed_extended_seed_and_mnemonic_helpers_cover_round_trips() {
    let seed = Seed::generate().expect("random seed");
    let seed_hex = seed.to_hex_prefixed();
    let recovered_seed = Seed::from_hex(&seed_hex).expect("seed from hex");
    assert_eq!(seed, recovered_seed);
    assert_eq!(seed.sha256().len(), 32);
    assert_eq!(seed.shake256(96).len(), 96);
    assert!(Seed::from_bytes(&[0_u8; 1]).is_err());

    let descriptor = Descriptor::mldsa87();
    let extended_seed = ExtendedSeed::new(descriptor, &seed).expect("extended seed");
    let extended_seed_hex = extended_seed.to_hex_prefixed();
    let recovered_extended_seed =
        ExtendedSeed::from_hex(&extended_seed_hex).expect("extended seed from hex");
    assert_eq!(extended_seed, recovered_extended_seed);
    assert_eq!(recovered_extended_seed.descriptor(), descriptor);
    assert_eq!(recovered_extended_seed.seed(), seed);

    let mnemonic = bin_to_mnemonic(extended_seed.as_bytes()).expect("mnemonic");
    let mnemonic_bytes = mnemonic_to_bin(&mnemonic).expect("mnemonic to bin");
    assert_eq!(mnemonic_bytes.as_slice(), extended_seed.as_bytes().as_slice());
    assert!(mnemonic_to_bin("aback invalid").is_err());
    assert!(bin_to_mnemonic(&[1_u8]).is_err());

    let mut zeroized_seed = seed.clone();
    zeroized_seed.zeroize();
    assert!(zeroized_seed.as_bytes().iter().all(|byte| *byte == 0));

    let mut zeroized_extended_seed = extended_seed.clone();
    zeroized_extended_seed.zeroize();
    assert!(zeroized_extended_seed.as_bytes().iter().all(|byte| *byte == 0));

    assert!(ExtendedSeed::new(Descriptor::new([9, 0, 0]), &seed).is_err());
    assert!(ExtendedSeed::from_bytes(&[0_u8; 4]).is_err());
}

#[test]
fn mldsa_public_api_covers_generation_import_export_and_zeroization() {
    let generated = MlDsa87::generate().expect("generated signer");
    let seed_hex = generated.hex_seed();
    let imported = MlDsa87::from_hex_seed(&seed_hex).expect("imported signer");
    assert_eq!(generated.public_key_bytes(), imported.public_key_bytes());

    let message = b"detached signatures in wasm";
    let signature = generated.sign(b"context", message).expect("signature");
    assert_eq!(signature.len(), ML_DSA_87_SIGNATURE_SIZE);
    assert_eq!(
        extract_message(&generated.sign_attached(b"context", message).expect("sealed"))
            .expect("message"),
        message
    );
    assert_eq!(extract_signature(&signature).expect("signature slice"), signature);
    assert!(extract_signature(&signature[..signature.len() - 1]).is_none());
    assert_eq!(extract_message(&signature).expect("empty message"), b"");

    let sealed = imported.sign_attached(b"context", message).expect("sealed message");
    let opened =
        open(b"context", &sealed, &imported.public_key_bytes()).expect("open").expect("opened");
    assert_eq!(opened, message);
    assert!(
        open(b"context", &[1_u8; 4], &imported.public_key_bytes()).expect("short open").is_none()
    );

    assert!(imported.verify(b"context", message, &signature).expect("verify"));
    assert!(MlDsa87::from_hex_seed("0x00").is_err());
    assert!(
        open(b"context", &sealed, &[0_u8; ML_DSA_87_PUBLIC_KEY_SIZE],)
            .expect("invalid verification")
            .is_none()
    );

    let mut zeroized = imported.clone();
    zeroized.zeroize();
    assert!(zeroized.seed().iter().all(|byte| *byte == 0));
    assert!(zeroized.secret_key_bytes().iter().all(|byte| *byte == 0));

    assert!(validate_mldsa_public_key(&imported.public_key_bytes()).is_ok());
    assert!(validate_mldsa_secret_key(imported.secret_key_bytes().as_slice()).is_ok());
    assert!(matches!(
        validate_mldsa_secret_key(&[0_u8; 1]),
        Err(QrllibError::InvalidMlDsaSecretKeySize(1, ML_DSA_87_SECRET_KEY_SIZE))
    ));
    assert!(matches!(
        validate_mldsa_public_key(&[0_u8; 1]),
        Err(QrllibError::InvalidPublicKeySize {
            wallet_type: WalletType::MlDsa87,
            actual: 1,
            expected: ML_DSA_87_PUBLIC_KEY_SIZE,
        })
    ));
}

#[test]
fn wallet_api_covers_seed_imports_generation_verification_and_zeroization() {
    let seed = Seed::from_bytes(&[11_u8; SEED_SIZE]).expect("seed");
    let wallet = MlDsa87Wallet::from_seed(seed.clone()).expect("wallet from seed");
    let wallet_from_raw_hex =
        MlDsa87Wallet::from_hex_seed(&seed.to_hex_prefixed()).expect("wallet from raw seed");
    assert_eq!(wallet.address(), wallet_from_raw_hex.address());

    let generated_wallet = MlDsa87Wallet::generate().expect("generated wallet");
    let signature = generated_wallet.sign(b"browser signing flow").expect("signature");
    assert!(verify_mldsa87_wallet_signature(
        b"browser signing flow",
        &signature,
        &generated_wallet.public_key(),
        generated_wallet.descriptor(),
    ));
    assert!(!verify_mldsa87_wallet_signature(
        b"browser signing flow",
        &signature,
        &generated_wallet.public_key(),
        Descriptor::new([0, 0, 0]),
    ));
    assert!(
        !verify_mldsa87_wallet_signature(
            b"browser signing flow",
            &signature,
            &generated_wallet.public_key(),
            Descriptor::new([WalletType::MlDsa87.code(), 0x01, 0x00]),
        ),
        "non-canonical ML-DSA-87 descriptor must not verify"
    );
    assert!(
        !verify_mldsa87_wallet_signature(
            b"browser signing flow",
            &signature,
            &generated_wallet.public_key(),
            Descriptor::new([WalletType::MlDsa87.code(), 0x00, 0xff]),
        ),
        "non-canonical ML-DSA-87 descriptor must not verify"
    );

    let wallet_hex = wallet.hex_seed().expect("wallet hex");
    let wallet_from_extended_hex =
        MlDsa87Wallet::from_hex_extended_seed(&wallet_hex).expect("wallet from extended hex");
    assert_eq!(wallet.address(), wallet_from_extended_hex.address());

    // `SPHINCSPLUS_256S` is not a valid common wallet descriptor
    // (TOB-QRLLIB-4, parity with go-qrllib's `descriptor.Descriptor.IsValid`),
    // so the common `ExtendedSeed` constructor refuses it outright rather
    // than deferring the rejection to `MlDsa87Wallet::from_extended_seed`.
    assert!(
        ExtendedSeed::new(Descriptor::new([WalletType::SphincsPlus256s.code(), 0, 0]), &seed)
            .is_err(),
        "SPHINCS+ descriptor must not produce a common extended seed"
    );

    let mut zeroized_wallet = wallet_from_extended_hex;
    zeroized_wallet.zeroize();
    assert!(zeroized_wallet.seed().as_bytes().iter().all(|byte| *byte == 0));
    assert!(zeroized_wallet.secret_key().iter().all(|byte| *byte == 0));
}

/// The raw SPHINCS+ primitive is ungated — it stays available in every build.
#[test]
fn sphincs_primitive_covers_generation_and_imports() {
    let generated = SphincsPlus256s::generate().expect("generated signer");
    assert_eq!(generated.public_key_bytes().len(), SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE);

    let imported = SphincsPlus256s::from_hex_seed(&generated.hex_seed()).expect("imported signer");
    assert_eq!(generated.public_key_bytes(), imported.public_key_bytes());
    assert!(SphincsPlus256s::from_hex_seed("0x00").is_err());
}

/// The SPHINCS+ *wallet* path needs the gated issuance opt-in. The runtime
/// helper is compiled only into debug builds or builds with
/// `experimental-sphincsplus-issuance` (TOB-QRLLIB-4 / CIPH-RUSTQRL-6), and
/// integration tests do not inherit the crate's own `cfg(test)` scope, so this
/// test carries the same cfg and `cargo test --release` still compiles without
/// the feature. Default `cargo test` and `cargo llvm-cov` are debug builds and
/// run it as before.
#[cfg(any(debug_assertions, feature = "experimental-sphincsplus-issuance"))]
#[test]
fn sphincs_wallet_api_covers_generation_imports() {
    use qrllib::{SphincsPlus256sWallet, enable_experimental_sphincsplus_issuance_for_testing};

    // Flip the runtime bypass before constructing any wallet from this test.
    enable_experimental_sphincsplus_issuance_for_testing();

    let seed = Seed::from_bytes(&[23_u8; SEED_SIZE]).expect("seed");
    let wallet = SphincsPlus256sWallet::from_hex_seed(&seed.to_hex_prefixed())
        .expect("wallet from raw seed");
    assert_eq!(wallet.seed(), seed);

    let generated_wallet = SphincsPlus256sWallet::generate().expect("generated wallet");
    assert!(is_valid_address(&generated_wallet.address_string()));

    // The extended-seed importers bypass the common descriptor policy (which
    // rejects SPHINCS+) but still length-check their input, mirroring the raw
    // `copy(extendedSeed[:], bin)` in go-qrllib's constructors.
    assert!(SphincsPlus256sWallet::from_hex_extended_seed("0x00").is_err());
    assert!(SphincsPlus256sWallet::from_hex_extended_seed("nothex").is_err());
    assert!(SphincsPlus256sWallet::from_mnemonic("aback aback").is_err());

    // A round trip through the SPHINCS+-specific extended-seed layout.
    let hex_extended = wallet.hex_seed().expect("hex extended seed");
    assert_eq!(
        SphincsPlus256sWallet::from_hex_extended_seed(&hex_extended)
            .expect("wallet from extended hex")
            .address(),
        wallet.address()
    );
    assert_eq!(
        SphincsPlus256sWallet::from_mnemonic(&wallet.mnemonic().expect("mnemonic"))
            .expect("wallet from mnemonic")
            .address(),
        wallet.address()
    );
}

#[test]
fn error_messages_remain_human_readable() {
    let error = QrllibError::from(getrandom::Error::UNSUPPORTED);
    assert!(error.to_string().contains("getrandom"));
    assert_eq!(QrllibError::InvalidDescriptor.to_string(), "invalid descriptor");
    assert_eq!(
        QrllibError::InvalidMlDsaSeedSize(1, ML_DSA_87_CRYPTO_SEED_SIZE).to_string(),
        "invalid ML-DSA seed size 1, expected 32"
    );
    // Sentinel exposed for parity with go-qrllib's
    // `common.ErrWalletTypeNotVerifiable`.
    let not_verifiable =
        QrllibError::WalletTypeNotVerifiable(WalletType::SphincsPlus256s).to_string();
    assert!(not_verifiable.contains("SPHINCSPLUS_256S"));
    assert!(not_verifiable.contains("verification is gated"));
}
