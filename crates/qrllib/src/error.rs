use crate::wallet_type::WalletType;

#[derive(Debug, thiserror::Error)]
pub enum QrllibError {
    #[error("randomness failure: {0}")]
    Randomness(String),

    #[error("hex decode failed: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("invalid descriptor")]
    InvalidDescriptor,

    #[error("invalid descriptor size {0}, expected {1}")]
    InvalidDescriptorSize(usize, usize),

    #[error("unknown wallet type: {0}")]
    UnknownWalletType(u8),

    #[error("{wallet_type} invalid public key size {actual}, expected {expected}")]
    InvalidPublicKeySize { wallet_type: WalletType, actual: usize, expected: usize },

    #[error("invalid ML-DSA seed size {0}, expected {1}")]
    InvalidMlDsaSeedSize(usize, usize),

    #[error("invalid ML-DSA secret key size {0}, expected {1}")]
    InvalidMlDsaSecretKeySize(usize, usize),

    #[error("invalid ML-DSA context size {0}, expected at most {1}")]
    InvalidMlDsaContextSize(usize, usize),

    #[error("ML-DSA secret key is zeroized")]
    MlDsaSecretKeyZeroized,

    #[error("invalid Dilithium seed size {0}, expected {1}")]
    InvalidDilithiumSeedSize(usize, usize),

    #[error("invalid SPHINCS+ seed size {0}, expected {1}")]
    InvalidSphincsSeedSize(usize, usize),

    #[error("invalid seed size {0}, expected {1}")]
    InvalidSeedSize(usize, usize),

    #[error("invalid extended seed length {0}, expected {1}")]
    InvalidExtendedSeedSize(usize, usize),

    #[error("invalid ML-DSA signature size {0}, expected {1}")]
    InvalidSignatureSize(usize, usize),

    #[error("invalid Dilithium public key size {0}, expected {1}")]
    InvalidDilithiumPublicKeySize(usize, usize),

    #[error("invalid Dilithium secret key size {0}, expected {1}")]
    InvalidDilithiumSecretKeySize(usize, usize),

    #[error("Dilithium secret key is zeroized")]
    DilithiumSecretKeyZeroized,

    #[error("invalid word in mnemonic")]
    InvalidMnemonicWord,

    #[error("word count = {0} must be even")]
    InvalidMnemonicWordCount(usize),

    #[error("byte count needs to be a multiple of 3")]
    InvalidMnemonicByteCount,

    #[error("invalid XMSS hash function: {0}")]
    InvalidXmssHashFunction(u8),

    #[error("invalid XMSS height: {0}")]
    InvalidXmssHeight(u8),

    #[error("invalid XMSS BDS parameters")]
    InvalidXmssBdsParams,

    #[error("invalid XMSS WOTS parameter: {0}")]
    InvalidXmssWotsParameter(u32),

    #[error("invalid XMSS key length: {0}")]
    InvalidXmssKeyLength(usize),

    #[error("XMSS OTS index exceeds maximum")]
    XmssOtsIndexTooHigh,

    #[error("cannot rewind XMSS OTS index")]
    XmssOtsIndexRewind,

    #[error("internal XMSS error")]
    XmssInternal,

    #[error("invalid legacy wallet type: {0}")]
    InvalidLegacyWalletType(u8),

    #[error("unsupported legacy XMSS address format: {0}")]
    UnsupportedLegacyAddressFormat(u8),
}

pub type Result<T> = core::result::Result<T, QrllibError>;

impl From<getrandom::Error> for QrllibError {
    fn from(value: getrandom::Error) -> Self {
        Self::Randomness(value.to_string())
    }
}
