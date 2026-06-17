use crate::{
    bin_to_mnemonic,
    error::{QrllibError, Result},
    xmss::{
        XMSS_MAX_HEIGHT, XMSS_PUBLIC_KEY_SIZE, XMSS_SEED_SIZE, Xmss, XmssHashFunction, XmssHeight,
        get_xmss_height_from_sig_size, verify_xmss,
    },
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const LEGACY_XMSS_DESCRIPTOR_SIZE: usize = 3;
pub const LEGACY_XMSS_SEED_SIZE: usize = XMSS_SEED_SIZE;
pub const LEGACY_XMSS_EXTENDED_SEED_SIZE: usize =
    LEGACY_XMSS_DESCRIPTOR_SIZE + LEGACY_XMSS_SEED_SIZE;
pub const LEGACY_XMSS_ADDRESS_SIZE: usize = 39;
pub const LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE: usize =
    LEGACY_XMSS_DESCRIPTOR_SIZE + XMSS_PUBLIC_KEY_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LegacyWalletType {
    Xmss = 0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LegacyAddrFormatType {
    Sha2562x = 0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QrlDescriptor {
    hash_function: XmssHashFunction,
    signature_type: LegacyWalletType,
    height: XmssHeight,
    addr_format_type: LegacyAddrFormatType,
}

/// Legacy QRL XMSS wallet wrapper.
///
/// Wraps an [`Xmss`] signer with the QRL descriptor, 48-byte QRL seed, and
/// address-format metadata required for legacy QRL addresses.
///
/// Inherits the XMSS statefulness contract from [`Xmss`]: this type does
/// **not** implement [`Clone`], and restoring from backup without reconciling
/// the OTS index causes one-time-key reuse. See the [`Xmss`] docs and
/// `SECURITY.md` for the full threat model and operational rules.
#[derive(Debug)]
pub struct LegacyXmssWallet {
    seed: [u8; LEGACY_XMSS_SEED_SIZE],
    descriptor: QrlDescriptor,
    xmss: Xmss,
}

impl TryFrom<u8> for LegacyWalletType {
    type Error = QrllibError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Xmss),
            _ => Err(QrllibError::InvalidLegacyWalletType(value)),
        }
    }
}

impl LegacyWalletType {
    pub fn is_valid(self) -> bool {
        matches!(self, Self::Xmss)
    }
}

impl TryFrom<u8> for LegacyAddrFormatType {
    type Error = QrllibError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Sha2562x),
            _ => Err(QrllibError::UnsupportedLegacyAddressFormat(value)),
        }
    }
}

impl QrlDescriptor {
    pub fn new(
        height: XmssHeight,
        hash_function: XmssHashFunction,
        signature_type: LegacyWalletType,
        addr_format_type: LegacyAddrFormatType,
    ) -> Self {
        Self { hash_function, signature_type, height, addr_format_type }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != LEGACY_XMSS_DESCRIPTOR_SIZE {
            return Err(QrllibError::InvalidDescriptorSize(
                bytes.len(),
                LEGACY_XMSS_DESCRIPTOR_SIZE,
            ));
        }

        Ok(Self {
            hash_function: XmssHashFunction::try_from(bytes[0] & 0x0f)?,
            signature_type: LegacyWalletType::try_from((bytes[0] >> 4) & 0x0f)?,
            height: XmssHeight::from_descriptor_byte(bytes[1])?,
            addr_format_type: LegacyAddrFormatType::try_from((bytes[1] & 0xf0) >> 4)?,
        })
    }

    pub fn from_extended_seed(bytes: &[u8; LEGACY_XMSS_EXTENDED_SEED_SIZE]) -> Result<Self> {
        Self::from_bytes(&bytes[..LEGACY_XMSS_DESCRIPTOR_SIZE])
    }

    pub fn from_extended_public_key(
        bytes: &[u8; LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE],
    ) -> Result<Self> {
        Self::from_bytes(&bytes[..LEGACY_XMSS_DESCRIPTOR_SIZE])
    }

    pub fn hash_function(&self) -> XmssHashFunction {
        self.hash_function
    }

    pub fn signature_type(&self) -> LegacyWalletType {
        self.signature_type
    }

    pub fn height(&self) -> XmssHeight {
        self.height
    }

    pub fn addr_format_type(&self) -> LegacyAddrFormatType {
        self.addr_format_type
    }

    pub fn to_bytes(self) -> [u8; LEGACY_XMSS_DESCRIPTOR_SIZE] {
        let mut output = [0_u8; LEGACY_XMSS_DESCRIPTOR_SIZE];
        output[0] = ((self.signature_type as u8) << 4) | ((self.hash_function as u8) & 0x0f);
        output[1] = ((self.addr_format_type as u8) << 4)
            | self.height.descriptor_byte().unwrap_or_default();
        output
    }
}

pub fn get_xmss_address_from_pk(
    extended_public_key: [u8; LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE],
) -> Result<[u8; LEGACY_XMSS_ADDRESS_SIZE]> {
    let descriptor = QrlDescriptor::from_extended_public_key(&extended_public_key)?;
    // Coverage: unreachable today because `LegacyAddrFormatType` has a single
    // variant (`Sha2562x`); `TryFrom<u8>` already rejects any other byte at
    // parse time. Kept as a forward-compatibility checkpoint so that adding a
    // new variant forces explicit handling here.
    if descriptor.addr_format_type() != LegacyAddrFormatType::Sha2562x {
        //coverage:ignore start reason=defensively-unreachable
        return Err(QrllibError::UnsupportedLegacyAddressFormat(
            descriptor.addr_format_type() as u8
        ));
        //coverage:ignore end
    }

    let mut address = [0_u8; LEGACY_XMSS_ADDRESS_SIZE];
    let descriptor_bytes = descriptor.to_bytes();
    address[..LEGACY_XMSS_DESCRIPTOR_SIZE].copy_from_slice(&descriptor_bytes);

    let hashed_key = Sha256::digest(extended_public_key);
    address[LEGACY_XMSS_DESCRIPTOR_SIZE..LEGACY_XMSS_DESCRIPTOR_SIZE + 32]
        .copy_from_slice(&hashed_key);

    let checksum = Sha256::digest(&address[..LEGACY_XMSS_DESCRIPTOR_SIZE + 32]);
    address[LEGACY_XMSS_DESCRIPTOR_SIZE + 32..].copy_from_slice(&checksum[28..32]);
    Ok(address)
}

pub fn is_valid_xmss_address(address: [u8; LEGACY_XMSS_ADDRESS_SIZE]) -> bool {
    let Ok(descriptor) = QrlDescriptor::from_bytes(&address[..LEGACY_XMSS_DESCRIPTOR_SIZE]) else {
        return false;
    };
    // Coverage: see `get_xmss_address_from_pk` — single-variant forward-compat guard.
    if descriptor.addr_format_type() != LegacyAddrFormatType::Sha2562x {
        //coverage:ignore reason=defensively-unreachable
        return false;
    }

    let checksum = Sha256::digest(&address[..LEGACY_XMSS_DESCRIPTOR_SIZE + 32]);
    address[LEGACY_XMSS_DESCRIPTOR_SIZE + 32..] == checksum[28..32]
}

impl LegacyXmssWallet {
    pub fn new_from_seed(
        seed: [u8; LEGACY_XMSS_SEED_SIZE],
        height: XmssHeight,
        hash_function: XmssHashFunction,
        addr_format_type: LegacyAddrFormatType,
    ) -> Result<Self> {
        // Coverage: unreachable today because every `XmssHeight` constructor
        // (`new`, `from_u32`, `from_descriptor_byte`) already enforces
        // `value <= XMSS_MAX_HEIGHT`. Kept as a defence-in-depth guard against
        // a future constructor that might skip the check.
        if height.as_u8() > XMSS_MAX_HEIGHT {
            //coverage:ignore reason=defensively-unreachable
            return Err(QrllibError::InvalidXmssHeight(height.as_u8()));
        }

        let descriptor =
            QrlDescriptor::new(height, hash_function, LegacyWalletType::Xmss, addr_format_type);
        let xmss = Xmss::initialize_tree(height, hash_function, &seed)?;

        Ok(Self { seed, descriptor, xmss })
    }

    pub fn new_from_extended_seed(
        extended_seed: [u8; LEGACY_XMSS_EXTENDED_SEED_SIZE],
    ) -> Result<Self> {
        let descriptor = QrlDescriptor::from_extended_seed(&extended_seed)?;
        let mut seed = [0_u8; LEGACY_XMSS_SEED_SIZE];
        seed.copy_from_slice(&extended_seed[LEGACY_XMSS_DESCRIPTOR_SIZE..]);
        let xmss = Xmss::initialize_tree(descriptor.height(), descriptor.hash_function(), &seed)?;

        Ok(Self { seed, descriptor, xmss })
    }

    pub fn new(height: XmssHeight, hash_function: XmssHashFunction) -> Result<Self> {
        let mut seed = [0_u8; LEGACY_XMSS_SEED_SIZE];
        getrandom::getrandom(&mut seed)?;
        Self::new_from_seed(seed, height, hash_function, LegacyAddrFormatType::Sha2562x)
    }

    pub fn set_index(&mut self, new_index: u32) -> Result<()> {
        self.xmss.set_index(new_index)
    }

    pub fn height(&self) -> XmssHeight {
        self.xmss.height()
    }

    pub fn seed(&self) -> Zeroizing<[u8; LEGACY_XMSS_SEED_SIZE]> {
        Zeroizing::new(self.seed)
    }

    pub fn extended_seed(&self) -> [u8; LEGACY_XMSS_EXTENDED_SEED_SIZE] {
        let mut output = [0_u8; LEGACY_XMSS_EXTENDED_SEED_SIZE];
        let descriptor = self.descriptor.to_bytes();
        output[..LEGACY_XMSS_DESCRIPTOR_SIZE].copy_from_slice(&descriptor);
        output[LEGACY_XMSS_DESCRIPTOR_SIZE..].copy_from_slice(&self.seed);
        output
    }

    pub fn hex_seed(&self) -> String {
        format!("0x{}", hex::encode(self.extended_seed()))
    }

    pub fn mnemonic(&self) -> Result<String> {
        bin_to_mnemonic(&self.extended_seed())
    }

    pub fn root(&self) -> Vec<u8> {
        self.xmss.root()
    }

    pub fn public_key(&self) -> [u8; LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE] {
        let mut output = [0_u8; LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE];
        let descriptor = self.descriptor.to_bytes();
        let root = self.root();
        let public_seed = self.xmss.public_seed();

        output[..LEGACY_XMSS_DESCRIPTOR_SIZE].copy_from_slice(&descriptor);
        output[LEGACY_XMSS_DESCRIPTOR_SIZE..LEGACY_XMSS_DESCRIPTOR_SIZE + 32]
            .copy_from_slice(&root);
        output[LEGACY_XMSS_DESCRIPTOR_SIZE + 32..].copy_from_slice(&public_seed);
        output
    }

    pub fn secret_key(&self) -> Zeroizing<Vec<u8>> {
        self.xmss.secret_key()
    }

    pub fn address(&self) -> Result<[u8; LEGACY_XMSS_ADDRESS_SIZE]> {
        get_xmss_address_from_pk(self.public_key())
    }

    pub fn index(&self) -> u32 {
        self.xmss.index()
    }

    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.xmss.sign(message)
    }

    pub fn descriptor(&self) -> QrlDescriptor {
        self.descriptor
    }

    pub fn zeroize(&mut self) {
        self.seed.zeroize();
        self.xmss.zeroize();
    }
}

impl Drop for LegacyXmssWallet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn verify_legacy_xmss(
    message: &[u8],
    signature: &[u8],
    extended_public_key: [u8; LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE],
) -> bool {
    let Ok(height) = get_xmss_height_from_sig_size(signature.len() as u32, 16) else {
        return false;
    };
    let Ok(descriptor) = QrlDescriptor::from_extended_public_key(&extended_public_key) else {
        return false;
    };
    // Coverage: unreachable today because `LegacyWalletType` has a single
    // variant (`Xmss`); `TryFrom<u8>` already rejects any other byte at parse
    // time. Kept as a forward-compatibility checkpoint.
    if descriptor.signature_type() != LegacyWalletType::Xmss {
        //coverage:ignore reason=defensively-unreachable
        return false;
    }
    if descriptor.height() != height {
        return false;
    }

    verify_xmss(
        descriptor.hash_function(),
        message,
        signature,
        &extended_public_key[LEGACY_XMSS_DESCRIPTOR_SIZE..],
    )
}

#[cfg(test)]
mod tests {
    use super::{
        LEGACY_XMSS_ADDRESS_SIZE, LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE,
        LEGACY_XMSS_EXTENDED_SEED_SIZE, LEGACY_XMSS_SEED_SIZE, LegacyAddrFormatType,
        LegacyWalletType, LegacyXmssWallet, QrlDescriptor, get_xmss_address_from_pk,
        is_valid_xmss_address, verify_legacy_xmss,
    };
    use crate::QrllibError;
    use crate::xmss::{XmssHashFunction, XmssHeight};

    fn zero_seed_wallet(height: u8) -> LegacyXmssWallet {
        LegacyXmssWallet::new_from_seed(
            [0_u8; LEGACY_XMSS_SEED_SIZE],
            XmssHeight::new(height).expect("height"),
            XmssHashFunction::Shake128,
            LegacyAddrFormatType::Sha2562x,
        )
        .expect("wallet")
    }

    #[test]
    fn legacy_descriptor_round_trip_matches_go_layout() {
        let descriptor = QrlDescriptor::new(
            XmssHeight::new(6).expect("height"),
            XmssHashFunction::Shake256,
            LegacyWalletType::Xmss,
            LegacyAddrFormatType::Sha2562x,
        );
        let bytes = descriptor.to_bytes();
        let recovered = QrlDescriptor::from_bytes(&bytes).expect("descriptor");
        assert_eq!(recovered.height().as_u8(), 6);
        assert_eq!(recovered.hash_function(), XmssHashFunction::Shake256);
        assert_eq!(recovered.signature_type(), LegacyWalletType::Xmss);
        assert_eq!(recovered.addr_format_type(), LegacyAddrFormatType::Sha2562x);
    }

    #[test]
    fn legacy_wallet_known_zero_seed_vectors_match_go() {
        let wallet = zero_seed_wallet(4);
        assert_eq!(
            hex::encode(wallet.public_key()),
            "010200c25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d"
        );
        assert_eq!(
            hex::encode(wallet.address().expect("address")),
            "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897"
        );
        assert_eq!(
            hex::encode(wallet.extended_seed()),
            "010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn legacy_wallet_height_six_vector_matches_go() {
        let wallet = zero_seed_wallet(6);
        assert_eq!(
            hex::encode(wallet.public_key()),
            "010300859060f15adc3825adeec85c7483d868e898bc5117d0cff04ab1343916d407af3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d"
        );
        assert_eq!(
            hex::encode(wallet.address().expect("address")),
            "0103008b0e18dd0bac2c3fdc9a48e10fc466eef899ef074449d12ddf050317b2083527aee74bc3"
        );
    }

    #[test]
    fn legacy_wallet_mnemonic_matches_go_zero_seed_fixture() {
        let wallet = zero_seed_wallet(4);
        assert_eq!(
            wallet.mnemonic().expect("mnemonic"),
            "absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback"
        );
    }

    #[test]
    fn legacy_wallet_sign_and_verify_round_trip() {
        let mut wallet = zero_seed_wallet(4);
        let message = b"legacy xmss";
        let signature = wallet.sign(message).expect("signature");
        assert!(verify_legacy_xmss(message, &signature, wallet.public_key()));
        assert!(!verify_legacy_xmss(b"tampered", &signature, wallet.public_key()));
    }

    #[test]
    fn legacy_wallet_index_rules_match_go() {
        let mut wallet = zero_seed_wallet(4);
        assert!(wallet.set_index(15).is_ok());
        assert_eq!(wallet.index(), 15);
        assert!(wallet.set_index(16).is_err());
        assert!(wallet.set_index(20).is_err());
    }

    #[test]
    fn legacy_wallet_can_be_restored_from_extended_seed() {
        let wallet = zero_seed_wallet(4);
        let restored = LegacyXmssWallet::new_from_extended_seed(wallet.extended_seed())
            .expect("restored wallet");
        assert_eq!(wallet.public_key(), restored.public_key());
        assert_eq!(wallet.seed(), restored.seed());
    }

    #[test]
    fn legacy_address_validation_rejects_bad_formats() {
        let wallet = zero_seed_wallet(4);
        let address = wallet.address().expect("address");
        assert!(is_valid_xmss_address(address));

        let mut invalid = [0_u8; LEGACY_XMSS_ADDRESS_SIZE];
        invalid[0] = 0xff;
        assert!(!is_valid_xmss_address(invalid));
    }

    #[test]
    fn legacy_address_from_known_public_key_is_valid() {
        let mut public_key = [0_u8; LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE];
        let pk = hex::decode(
            "01050043559486d0bb65088477848ad81224dca1545fa31ae33d0f49a6a0721e88f972dd9228b48b1ccf4f83adc265e00dc887b791641f7da0c577899d339b126f3d04",
        )
        .expect("hex");
        public_key.copy_from_slice(&pk);
        let address = get_xmss_address_from_pk(public_key).expect("address");
        assert!(is_valid_xmss_address(address));
    }

    #[test]
    fn legacy_descriptor_and_seed_lengths_are_stable() {
        assert_eq!(LEGACY_XMSS_EXTENDED_SEED_SIZE, 51);
        assert_eq!(LEGACY_XMSS_EXTENDED_PUBLIC_KEY_SIZE, 67);
    }

    #[test]
    fn legacy_public_api_and_error_paths_are_covered() {
        assert!(LegacyWalletType::Xmss.is_valid());
        assert!(matches!(
            LegacyWalletType::try_from(1),
            Err(QrllibError::InvalidLegacyWalletType(1))
        ));
        assert!(matches!(
            LegacyAddrFormatType::try_from(1),
            Err(QrllibError::UnsupportedLegacyAddressFormat(1))
        ));
        assert!(matches!(
            QrlDescriptor::from_bytes(&[0_u8; 2]),
            Err(QrllibError::InvalidDescriptorSize(_, 3))
        ));
        assert!(matches!(
            QrlDescriptor::from_bytes(&[0x0f, 0x02, 0x00]),
            Err(QrllibError::InvalidXmssHashFunction(15))
        ));
        assert!(matches!(
            QrlDescriptor::from_bytes(&[0x10, 0x02, 0x00]),
            Err(QrllibError::InvalidLegacyWalletType(1))
        ));
        assert!(matches!(
            QrlDescriptor::from_bytes(&[0x00, 0x00, 0x00]),
            Err(QrllibError::InvalidXmssHeight(0))
        ));
        assert!(matches!(
            QrlDescriptor::from_bytes(&[0x00, 0x12, 0x00]),
            Err(QrllibError::UnsupportedLegacyAddressFormat(1))
        ));

        let mut wallet =
            LegacyXmssWallet::new(XmssHeight::new(4).expect("height"), XmssHashFunction::Shake128)
                .expect("random wallet");
        assert_eq!(wallet.height().as_u8(), 4);
        assert_eq!(wallet.descriptor().signature_type(), LegacyWalletType::Xmss);
        assert_eq!(wallet.hex_seed().len(), 2 + LEGACY_XMSS_EXTENDED_SEED_SIZE * 2);
        assert_eq!(wallet.secret_key().len(), crate::xmss::XMSS_SECRET_KEY_SIZE);

        let mut unsupported_addr_pk = wallet.public_key();
        unsupported_addr_pk[1] |= 0x10;
        assert!(matches!(
            get_xmss_address_from_pk(unsupported_addr_pk),
            Err(QrllibError::UnsupportedLegacyAddressFormat(1))
        ));

        let mut invalid_address = wallet.address().expect("address");
        invalid_address[1] |= 0x10;
        assert!(!is_valid_xmss_address(invalid_address));

        let message = b"legacy error coverage";
        let signature = wallet.sign(message).expect("signature");
        assert!(!verify_legacy_xmss(message, &[0_u8; 4], wallet.public_key()));

        let mut invalid_hash_pk = wallet.public_key();
        invalid_hash_pk[0] = 0x0f;
        assert!(!verify_legacy_xmss(message, &signature, invalid_hash_pk));

        let mut invalid_type_pk = wallet.public_key();
        invalid_type_pk[0] |= 0x10;
        assert!(!verify_legacy_xmss(message, &signature, invalid_type_pk));

        let mut invalid_height_pk = wallet.public_key();
        invalid_height_pk[1] = (invalid_height_pk[1] & 0xf0) | 0x03;
        assert!(!verify_legacy_xmss(message, &signature, invalid_height_pk));

        wallet.zeroize();
        assert!(wallet.seed().iter().all(|byte| *byte == 0));
        assert!(wallet.secret_key().iter().all(|byte| *byte == 0));
    }
}
