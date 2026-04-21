use crate::{
    DESCRIPTOR_SIZE,
    error::{QrllibError, Result},
    wallet_type::WalletType,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor([u8; DESCRIPTOR_SIZE]);

impl Descriptor {
    pub const fn new(bytes: [u8; DESCRIPTOR_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn mldsa87() -> Self {
        Self([WalletType::MlDsa87.code(), 0, 0])
    }

    pub const fn sphincsplus256s() -> Self {
        Self([WalletType::SphincsPlus256s.code(), 0, 0])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DESCRIPTOR_SIZE {
            return Err(QrllibError::InvalidDescriptorSize(bytes.len(), DESCRIPTOR_SIZE));
        }

        let mut descriptor = [0_u8; DESCRIPTOR_SIZE];
        descriptor.copy_from_slice(bytes);
        Ok(Self(descriptor))
    }

    pub const fn type_code(self) -> u8 {
        self.0[0]
    }

    pub fn wallet_type(self) -> Result<WalletType> {
        WalletType::try_from(self.type_code())
    }

    pub fn is_valid(self) -> bool {
        // Descriptor bytes 1–2 are a backwards-compatibility surface from
        // the legacy XMSS address format and are unused for ML-DSA-87 and
        // SPHINCS+-256s. Until a future schema formally defines them, only
        // the canonical `{type, 0x00, 0x00}` shape is accepted.
        self.wallet_type().is_ok() && self.0[1] == 0 && self.0[2] == 0
    }

    pub fn metadata(self) -> [u8; 2] {
        [self.0[1], self.0[2]]
    }

    pub const fn to_bytes(self) -> [u8; DESCRIPTOR_SIZE] {
        self.0
    }

    pub fn validate(self) -> Result<Self> {
        if self.is_valid() { Ok(self) } else { Err(QrllibError::InvalidDescriptor) }
    }
}

impl AsRef<[u8]> for Descriptor {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
