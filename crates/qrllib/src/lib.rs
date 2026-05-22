#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod address;
pub mod descriptor;
pub mod dilithium;
pub mod error;
mod lattice;
pub mod legacy_xmss;
pub mod mldsa;
pub mod mnemonic;
pub mod seed;
pub mod signing_context;
pub mod sphincsplus;
pub mod sphincsplus_wallet;
pub mod wallet;
pub mod wallet_type;
mod wordlist;
pub mod xmss;

pub use address::{
    format_address, get_address, is_valid_address, is_valid_checksum_address,
    to_checksum_address,
};
pub use descriptor::Descriptor;
pub use dilithium::{
    DILITHIUM_CRYPTO_SEED_SIZE, DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_SECRET_KEY_SIZE,
    DILITHIUM_SIGNATURE_SIZE, Dilithium, dilithium_extract_message, dilithium_extract_signature,
    dilithium_open, sign_dilithium_with_secret_key, sign_dilithium_with_secret_key_deterministic,
    validate_dilithium_public_key, validate_dilithium_secret_key, verify_dilithium_signature,
};
pub use error::{QrllibError, Result};
pub use legacy_xmss::{
    LEGACY_XMSS_ADDRESS_SIZE, LEGACY_XMSS_DESCRIPTOR_SIZE, LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE,
    LEGACY_XMSS_EXTENDED_SEED_SIZE, LEGACY_XMSS_SEED_SIZE, LegacyAddrFormatType, LegacyWalletType,
    LegacyXmssWallet, QrlDescriptor, get_xmss_address_from_pk, is_valid_xmss_address,
    verify_legacy_xmss,
};
pub use mldsa::{
    ML_DSA_87_CRYPTO_SEED_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE,
    ML_DSA_87_SIGNATURE_SIZE, MlDsa87, extract_message, extract_signature, open,
    sign_with_secret_key as sign_mldsa_with_secret_key,
    sign_with_secret_key_deterministic as sign_mldsa_with_secret_key_deterministic,
    validate_mldsa_public_key, validate_mldsa_secret_key,
};
pub use mnemonic::{bin_to_mnemonic, mnemonic_to_bin};
pub use seed::{ExtendedSeed, Seed};
pub use signing_context::{
    SIGNING_CONTEXT_PREFIX, SIGNING_CONTEXT_SIZE, SIGNING_CONTEXT_VERSION, signing_context,
};
pub use sphincsplus::{
    SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
    SPHINCS_PLUS_256S_SECRET_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, SphincsPlus256s,
    sphincsplus_extract_message, sphincsplus_extract_signature, sphincsplus_open,
    validate_sphincsplus_public_key, verify_sphincsplus_signature,
};
pub use sphincsplus_wallet::{SphincsPlus256sWallet, verify_sphincsplus_wallet_signature};
pub use wallet::{MlDsa87Wallet, verify_mldsa87_wallet_signature};
pub use wallet_type::{WalletType, enable_experimental_sphincsplus_issuance_for_testing};
pub use xmss::{
    XMSS_MAX_HEIGHT, XMSS_PUBLIC_KEY_SIZE, XMSS_SECRET_KEY_SIZE, XMSS_SEED_SIZE, XMSS_WOTS_PARAM_K,
    XMSS_WOTS_PARAM_N, XMSS_WOTS_PARAM_W, Xmss, XmssHashFunction, XmssHeight,
    get_xmss_height_from_sig_size, verify_xmss, verify_xmss_with_custom_wots_param_w,
};

pub const ADDRESS_SIZE: usize = 64;
pub const DESCRIPTOR_SIZE: usize = 3;
pub const SEED_SIZE: usize = 48;
pub const EXTENDED_SEED_SIZE: usize = DESCRIPTOR_SIZE + SEED_SIZE;
