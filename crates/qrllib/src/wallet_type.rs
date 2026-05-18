use crate::{
    SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
    error::{QrllibError, Result},
    mldsa::ML_DSA_87_PUBLIC_KEY_SIZE,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WalletType {
    SphincsPlus256s = 0,
    MlDsa87 = 1,
}

impl WalletType {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn expected_public_key_size(self) -> usize {
        match self {
            Self::SphincsPlus256s => SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
            Self::MlDsa87 => ML_DSA_87_PUBLIC_KEY_SIZE,
        }
    }

    /// Whether the QRL wallet layer will currently issue *new* wallets
    /// of this type. (TOB-QRLLIB-4.)
    ///
    /// - [`Self::MlDsa87`] — always `true`. ML-DSA-87 is the primary
    ///   recommended QRL v2 algorithm (FIPS 204).
    /// - [`Self::SphincsPlus256s`] — `true` only when the
    ///   `experimental-sphincsplus-issuance` Cargo feature is enabled
    ///   (or in in-crate tests). The implementation here is the
    ///   pre-FIPS-205 SPHINCS+ submission, QRL has not yet committed
    ///   to a specific SLH-DSA parameter set under FIPS 205, and
    ///   activating the wallet path now would commit users to a
    ///   parameter set that may change. The wallet type is reserved
    ///   in the descriptor format so existing addresses keep working
    ///   (see [`is_verifiable`]).
    ///
    /// [`is_verifiable`]: Self::is_verifiable
    pub const fn is_issuable(self) -> bool {
        match self {
            Self::MlDsa87 => true,
            Self::SphincsPlus256s => {
                cfg!(any(test, feature = "experimental-sphincsplus-issuance"))
            }
        }
    }

    /// Whether the QRL wallet layer will currently *verify* signatures
    /// for this wallet type. (TOB-QRLLIB-4.)
    ///
    /// Always `true` for both [`Self::MlDsa87`] and
    /// [`Self::SphincsPlus256s`] — existing addresses must continue to
    /// be verifiable regardless of the issuance gate. The pair
    /// (`is_issuable`, `is_verifiable`) lets a wallet type be
    /// "verify-only" (existing addresses keep working but new wallets
    /// cannot be created), which is the current SPHINCS+/SLH-DSA
    /// posture.
    pub const fn is_verifiable(self) -> bool {
        match self {
            Self::MlDsa87 | Self::SphincsPlus256s => true,
        }
    }
}

impl TryFrom<u8> for WalletType {
    type Error = QrllibError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::SphincsPlus256s),
            1 => Ok(Self::MlDsa87),
            _ => Err(QrllibError::UnknownWalletType(value)),
        }
    }
}

impl core::fmt::Display for WalletType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SphincsPlus256s => f.write_str("SPHINCSPLUS_256S"),
            Self::MlDsa87 => f.write_str("ML_DSA_87"),
        }
    }
}
