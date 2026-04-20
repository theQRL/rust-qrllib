use qrllib::{
    ADDRESS_SIZE, DESCRIPTOR_SIZE, DILITHIUM_CRYPTO_SEED_SIZE, DILITHIUM_PUBLIC_KEY_SIZE,
    DILITHIUM_SECRET_KEY_SIZE, DILITHIUM_SIGNATURE_SIZE, Descriptor, Dilithium, ExtendedSeed,
    ML_DSA_87_CRYPTO_SEED_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87,
    MlDsa87Wallet, QrllibError, SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE, Seed,
    SphincsPlus256s, SphincsPlus256sWallet, WalletType, bin_to_mnemonic, dilithium_extract_message,
    dilithium_extract_signature, dilithium_open, extract_message, extract_signature,
    format_address, get_address, is_valid_address, mnemonic_to_bin, open,
    sign_dilithium_with_secret_key, validate_dilithium_public_key, validate_dilithium_secret_key,
    verify_dilithium_signature, verify_mldsa87_wallet_signature,
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
    assert!(matches!(WalletType::try_from(9), Err(QrllibError::UnknownWalletType(9))));
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
    assert_eq!(mnemonic_bytes, extended_seed.as_bytes());
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
        extract_message(&generated.seal(b"context", message).expect("sealed")).expect("message"),
        message
    );
    assert_eq!(extract_signature(&signature).expect("signature slice"), signature);
    assert!(extract_signature(&signature[..signature.len() - 1]).is_none());
    assert_eq!(extract_message(&signature).expect("empty message"), b"");

    let sealed = imported.seal(b"context", message).expect("sealed message");
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
}

#[test]
fn dilithium_public_api_covers_generation_import_export_and_zeroization() {
    let generated = Dilithium::generate().expect("generated signer");
    let seed_hex = generated.hex_seed();
    let imported = Dilithium::from_hex_seed(&seed_hex).expect("imported signer");
    assert_eq!(generated.public_key_bytes(), imported.public_key_bytes());
    assert!(validate_dilithium_public_key(&imported.public_key_bytes()).is_ok());
    assert!(validate_dilithium_secret_key(imported.secret_key_bytes().as_slice()).is_ok());

    let message = b"legacy detached signatures in wasm";
    let signature = generated.sign(message).expect("signature");
    assert_eq!(signature.len(), DILITHIUM_SIGNATURE_SIZE);
    assert_eq!(
        dilithium_extract_message(&generated.seal(message).expect("sealed")).expect("message"),
        message
    );
    assert_eq!(dilithium_extract_signature(&signature).expect("signature slice"), signature);
    assert!(dilithium_extract_signature(&signature[..signature.len() - 1]).is_none());
    assert_eq!(dilithium_extract_message(&signature).expect("empty message"), b"");

    let sealed = imported.seal(message).expect("sealed message");
    let opened = dilithium_open(&sealed, &imported.public_key_bytes()).expect("opened");
    assert_eq!(opened, message);
    assert!(dilithium_open(&[1_u8; 4], &imported.public_key_bytes()).is_none());

    assert!(verify_dilithium_signature(message, &signature, &imported.public_key_bytes()));
    assert_eq!(
        signature,
        sign_dilithium_with_secret_key(message, imported.secret_key_bytes().as_slice())
            .expect("sign with secret key")
    );
    assert!(Dilithium::from_hex_seed("0x00").is_err());
    assert!(!verify_dilithium_signature(
        message,
        &signature,
        &[0_u8; DILITHIUM_PUBLIC_KEY_SIZE - 1]
    ));

    let mut zeroized = imported.clone();
    zeroized.zeroize();
    assert!(zeroized.seed().iter().all(|byte| *byte == 0));
    assert!(zeroized.secret_key_bytes().iter().all(|byte| *byte == 0));
    assert!(matches!(
        sign_dilithium_with_secret_key(message, zeroized.secret_key_bytes().as_slice()),
        Err(QrllibError::DilithiumSecretKeyZeroized)
    ));
    assert!(matches!(
        validate_dilithium_secret_key(&[0_u8; 1]),
        Err(QrllibError::InvalidDilithiumSecretKeySize(1, DILITHIUM_SECRET_KEY_SIZE))
    ));
    assert!(matches!(
        validate_dilithium_public_key(&[0_u8; 1]),
        Err(QrllibError::InvalidDilithiumPublicKeySize(1, DILITHIUM_PUBLIC_KEY_SIZE))
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

    let wallet_hex = wallet.hex_seed().expect("wallet hex");
    let wallet_from_extended_hex =
        MlDsa87Wallet::from_hex_extended_seed(&wallet_hex).expect("wallet from extended hex");
    assert_eq!(wallet.address(), wallet_from_extended_hex.address());

    let sphincs_seed =
        ExtendedSeed::new(Descriptor::new([WalletType::SphincsPlus256s.code(), 0, 0]), &seed)
            .expect("sphincs extended seed");
    assert!(MlDsa87Wallet::from_extended_seed(sphincs_seed).is_err());

    let mut zeroized_wallet = wallet_from_extended_hex;
    zeroized_wallet.zeroize();
    assert!(zeroized_wallet.seed().as_bytes().iter().all(|byte| *byte == 0));
    assert!(zeroized_wallet.secret_key().iter().all(|byte| *byte == 0));
}

#[test]
fn sphincs_public_and_wallet_api_cover_generation_imports() {
    let generated = SphincsPlus256s::generate().expect("generated signer");
    assert_eq!(generated.public_key_bytes().len(), SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE);

    let imported = SphincsPlus256s::from_hex_seed(&generated.hex_seed()).expect("imported signer");
    assert_eq!(generated.public_key_bytes(), imported.public_key_bytes());
    assert!(SphincsPlus256s::from_hex_seed("0x00").is_err());

    let seed = Seed::from_bytes(&[23_u8; SEED_SIZE]).expect("seed");
    let wallet = SphincsPlus256sWallet::from_hex_seed(&seed.to_hex_prefixed())
        .expect("wallet from raw seed");
    assert_eq!(wallet.seed(), seed);

    let generated_wallet = SphincsPlus256sWallet::generate().expect("generated wallet");
    assert!(is_valid_address(&generated_wallet.address_string()));
}

#[test]
fn error_messages_remain_human_readable() {
    let error = QrllibError::from(getrandom::Error::UNSUPPORTED);
    assert!(error.to_string().contains("getrandom"));
    assert_eq!(QrllibError::InvalidDescriptor.to_string(), "invalid descriptor");
    assert_eq!(
        QrllibError::InvalidDilithiumSeedSize(1, DILITHIUM_CRYPTO_SEED_SIZE).to_string(),
        "invalid Dilithium seed size 1, expected 32"
    );
}
