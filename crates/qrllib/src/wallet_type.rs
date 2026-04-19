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
