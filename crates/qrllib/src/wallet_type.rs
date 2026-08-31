use crate::{
    SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
    error::{QrllibError, Result},
    mldsa::ML_DSA_87_PUBLIC_KEY_SIZE,
};

/// QRL wallet type discriminant, mirroring go-qrllib's
/// `wallet/common/wallettype.WalletType`.
///
/// [`Self::SphincsPlus256s`] is a **reserved** constant, not a usable
/// production wallet type: QRL has not committed to a specific SLH-DSA
/// (FIPS 205) parameter set, and the implementation carried here is the
/// pre-FIPS SPHINCS+ submission. Every gate below therefore answers
/// `false` for it, exactly as the Go side does. The experimental
/// SPHINCS+ wallet path layers its own opt-in on top of these gates —
/// see [`crate::sphincsplus_wallet`].
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

    /// Whether this wallet type is valid in the production common wallet
    /// API today. (TOB-QRLLIB-4; parity with Go's
    /// `wallettype.WalletType.IsValid`.)
    ///
    /// [`Self::SphincsPlus256s`] remains a reserved constant but is not a
    /// valid wallet type until QRL activates a reviewed SLH-DSA path.
    pub const fn is_valid(self) -> bool {
        match self {
            Self::MlDsa87 => true,
            Self::SphincsPlus256s => false,
        }
    }

    /// Whether the QRL wallet layer will construct *new* wallets of this
    /// type. (TOB-QRLLIB-4; parity with Go's `IsIssuable`.)
    ///
    /// Wallet constructors call this before deriving key material and
    /// return [`QrllibError::WalletTypeNotIssuable`] on a `false` result.
    pub const fn is_issuable(self) -> bool {
        match self {
            Self::MlDsa87 => true,
            Self::SphincsPlus256s => false,
        }
    }

    /// Whether the QRL wallet layer has an active verification path for
    /// signatures produced under this wallet type. (TOB-QRLLIB-4; parity
    /// with Go's `IsVerifiable`.)
    ///
    /// [`Self::SphincsPlus256s`] is `false`: no signatures have ever been
    /// produced under it on QRL networks, so refusing verification today
    /// is consistent with the on-chain reality. Wallet-level verify
    /// helpers return `false` on a `false` result; the sentinel
    /// [`QrllibError::WalletTypeNotVerifiable`] is exposed for callers
    /// that need to distinguish "signature invalid" from "wallet type not
    /// currently supported".
    pub const fn is_verifiable(self) -> bool {
        match self {
            Self::MlDsa87 => true,
            Self::SphincsPlus256s => false,
        }
    }
}

impl TryFrom<u8> for WalletType {
    type Error = QrllibError;

    /// Validated byte → wallet-type conversion, mirroring Go's
    /// `wallettype.ToWalletType`.
    ///
    /// Only bytes naming a [`WalletType::is_valid`] type convert. The
    /// reserved [`WalletType::SphincsPlus256s`] discriminant (`0`) is
    /// therefore **rejected** here even though the variant exists — the
    /// experimental SPHINCS+ wallet path compares
    /// [`Descriptor::type_code`] against [`WalletType::code`] directly
    /// rather than going through this conversion, exactly as Go's
    /// `wallet/sphincsplus_256s` package does.
    ///
    /// [`Descriptor::type_code`]: crate::descriptor::Descriptor::type_code
    fn try_from(value: u8) -> Result<Self> {
        match value {
            v if v == Self::MlDsa87.code() => Ok(Self::MlDsa87),
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

#[cfg(test)]
mod tests {
    use super::WalletType;
    use crate::error::QrllibError;

    #[test]
    fn mldsa87_is_valid_issuable_and_verifiable() {
        // ML-DSA-87 is the primary recommended QRL v2 algorithm (FIPS 204)
        // and is the only production wallet type today.
        assert!(WalletType::MlDsa87.is_valid());
        assert!(WalletType::MlDsa87.is_issuable());
        assert!(WalletType::MlDsa87.is_verifiable());
    }

    #[test]
    fn sphincsplus_is_gated_on_every_axis() {
        // Parity with go-qrllib: SPHINCSPLUS_256S is a reserved constant,
        // not a valid/issuable/verifiable production wallet type
        // (TOB-QRLLIB-4). The experimental opt-in lives in
        // `sphincsplus_wallet`, not here.
        assert!(!WalletType::SphincsPlus256s.is_valid());
        assert!(!WalletType::SphincsPlus256s.is_issuable());
        assert!(!WalletType::SphincsPlus256s.is_verifiable());
    }

    #[test]
    fn try_from_accepts_only_valid_wallet_types() {
        assert_eq!(WalletType::try_from(1).expect("ML-DSA-87"), WalletType::MlDsa87);
        // The reserved SPHINCS+ discriminant does not convert, matching
        // Go's `ToWalletType`.
        assert!(matches!(WalletType::try_from(0), Err(QrllibError::UnknownWalletType(0))));
        assert!(matches!(WalletType::try_from(9), Err(QrllibError::UnknownWalletType(9))));
    }

    #[test]
    fn display_names_match_go_constants() {
        assert_eq!(WalletType::MlDsa87.to_string(), "ML_DSA_87");
        assert_eq!(WalletType::SphincsPlus256s.to_string(), "SPHINCSPLUS_256S");
    }
}
