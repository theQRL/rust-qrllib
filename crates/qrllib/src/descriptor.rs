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

    /// The reserved SPHINCS+-256s descriptor.
    ///
    /// This is **not** a valid common wallet descriptor: [`Self::is_valid`]
    /// returns `false` for it, so [`crate::address::get_address`] and
    /// [`crate::seed::ExtendedSeed`] reject it, matching go-qrllib's
    /// `descriptor.Descriptor.IsValid`. It exists for the experimental
    /// SPHINCS+ wallet path in [`crate::sphincsplus_wallet`], which
    /// validates descriptors against its own package-local rules exactly
    /// as Go's `wallet/sphincsplus_256s` package does.
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

    /// Whether the descriptor is well-formed for the production common
    /// wallet API. Parity with go-qrllib's `descriptor.Descriptor.IsValid`.
    ///
    /// Only ML-DSA-87 qualifies today. `SPHINCSPLUS_256S` stays a reserved
    /// enum value but is not a valid common wallet descriptor until QRL
    /// activates a reviewed SLH-DSA path (TOB-QRLLIB-4).
    ///
    /// Descriptor bytes 1–2 are a backwards-compatibility surface from the
    /// legacy XMSS address format and carry no defined semantics today.
    /// Until a future schema defines them, only the canonical
    /// `{type, 0x00, 0x00}` shape is accepted. Rejecting non-zero metadata
    /// collapses the valid set to one canonical ML-DSA-87 descriptor, so a
    /// single keypair cannot derive sibling addresses through the public API.
    pub fn is_valid(self) -> bool {
        self.wallet_type().is_ok_and(WalletType::is_valid) && self.0[1] == 0 && self.0[2] == 0
    }

    /// Whether the descriptor is well-formed **and** the library will
    /// currently construct *new* wallets of this type. Parity with Go's
    /// `descriptor.Descriptor.IsIssuable`.
    pub fn is_issuable(self) -> bool {
        self.is_valid() && self.wallet_type().is_ok_and(WalletType::is_issuable)
    }

    /// Whether the descriptor is well-formed **and** the library has an
    /// active verification path for signatures produced under this wallet
    /// type. Parity with Go's `descriptor.Descriptor.IsVerifiable`.
    pub fn is_verifiable(self) -> bool {
        self.is_valid() && self.wallet_type().is_ok_and(WalletType::is_verifiable)
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
