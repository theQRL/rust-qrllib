use crate::{
    ADDRESS_SIZE,
    address::{format_address, unsafe_get_address},
    descriptor::Descriptor,
    error::{QrllibError, Result},
    mldsa::{ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE, MlDsa87, verify_bytes},
    mnemonic::{bin_to_mnemonic, mnemonic_to_bin},
    seed::{ExtendedSeed, Seed},
    wallet_type::WalletType,
};

pub const ML_DSA_87_CONTEXT: &[u8] = b"ZOND";

#[derive(Clone, Debug)]
pub struct MlDsa87Wallet {
    descriptor: Descriptor,
    signer: MlDsa87,
    seed: Seed,
}

pub fn verify_mldsa87_wallet_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    descriptor: Descriptor,
) -> bool {
    if !matches!(descriptor.wallet_type(), Ok(WalletType::MlDsa87)) {
        return false;
    }

    verify_bytes(ML_DSA_87_CONTEXT, message, signature, public_key).unwrap_or(false)
}

impl MlDsa87Wallet {
    pub fn generate() -> Result<Self> {
        let seed = Seed::generate()?;
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: Seed) -> Result<Self> {
        let descriptor = Descriptor::mldsa87();
        let signer = MlDsa87::from_seed(seed.sha256());
        Ok(Self { descriptor, signer, seed })
    }

    pub fn from_hex_seed(value: &str) -> Result<Self> {
        let seed = Seed::from_hex(value)?;
        Self::from_seed(seed)
    }

    pub fn from_extended_seed(extended_seed: ExtendedSeed) -> Result<Self> {
        let descriptor = extended_seed.descriptor();
        if descriptor.wallet_type()? != WalletType::MlDsa87 {
            return Err(QrllibError::InvalidDescriptor);
        }
        Self::from_seed(extended_seed.seed())
    }

    pub fn from_hex_extended_seed(value: &str) -> Result<Self> {
        let extended_seed = ExtendedSeed::from_hex(value)?;
        Self::from_extended_seed(extended_seed)
    }

    pub fn from_mnemonic(value: &str) -> Result<Self> {
        let bytes = mnemonic_to_bin(value)?;
        let extended_seed = ExtendedSeed::from_bytes(&bytes)?;
        Self::from_extended_seed(extended_seed)
    }

    pub fn seed(&self) -> Seed {
        self.seed.clone()
    }

    pub fn extended_seed(&self) -> Result<ExtendedSeed> {
        ExtendedSeed::new(self.descriptor, &self.seed)
    }

    pub fn hex_seed(&self) -> Result<String> {
        Ok(self.extended_seed()?.to_hex_prefixed())
    }

    pub fn mnemonic(&self) -> Result<String> {
        bin_to_mnemonic(self.extended_seed()?.as_bytes())
    }

    pub fn descriptor(&self) -> Descriptor {
        self.descriptor
    }

    pub fn public_key(&self) -> [u8; ML_DSA_87_PUBLIC_KEY_SIZE] {
        self.signer.public_key_bytes()
    }

    pub fn secret_key(&self) -> [u8; crate::mldsa::ML_DSA_87_SECRET_KEY_SIZE] {
        self.signer.secret_key_bytes()
    }

    pub fn address(&self) -> [u8; ADDRESS_SIZE] {
        unsafe_get_address(&self.public_key(), self.descriptor)
    }

    pub fn address_string(&self) -> String {
        format_address(&self.address())
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; ML_DSA_87_SIGNATURE_SIZE]> {
        self.signer.sign(ML_DSA_87_CONTEXT, message)
    }

    pub fn zeroize(&mut self) {
        self.seed.zeroize();
        self.signer.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        address::is_valid_address,
        mldsa::ML_DSA_87_SIGNATURE_SIZE,
        seed::{ExtendedSeed, Seed},
        wallet::{MlDsa87Wallet, verify_mldsa87_wallet_signature},
    };

    #[test]
    fn deterministic_wallet_generation_matches_seed() {
        let seed = Seed::from_bytes(&[3_u8; crate::SEED_SIZE]).expect("seed");
        let wallet_a = MlDsa87Wallet::from_seed(seed.clone()).expect("wallet");
        let wallet_b = MlDsa87Wallet::from_seed(seed).expect("wallet");

        assert_eq!(wallet_a.public_key(), wallet_b.public_key());
        assert_eq!(wallet_a.address(), wallet_b.address());
        assert_eq!(wallet_a.descriptor(), wallet_b.descriptor());
    }

    #[test]
    fn extended_seed_and_mnemonic_round_trip() {
        let seed = Seed::from_bytes(&[1_u8; crate::SEED_SIZE]).expect("seed");
        let wallet = MlDsa87Wallet::from_seed(seed).expect("wallet");
        let extended_seed = wallet.extended_seed().expect("extended seed");
        let hex_seed = wallet.hex_seed().expect("hex seed");
        let mnemonic = wallet.mnemonic().expect("mnemonic");

        assert_eq!(
            MlDsa87Wallet::from_hex_extended_seed(&hex_seed).expect("wallet from hex").address(),
            wallet.address()
        );
        assert_eq!(
            MlDsa87Wallet::from_mnemonic(&mnemonic).expect("wallet from mnemonic").address(),
            wallet.address()
        );
        assert_eq!(
            ExtendedSeed::from_hex(&hex_seed).expect("extended seed from hex"),
            extended_seed
        );
    }

    #[test]
    fn wallet_signatures_verify() {
        let wallet =
            MlDsa87Wallet::from_seed(Seed::from_bytes(&[4_u8; crate::SEED_SIZE]).expect("seed"))
                .expect("wallet");
        let message = b"browser-ready signatures";
        let signature = wallet.sign(message).expect("sign");

        assert!(verify_mldsa87_wallet_signature(
            message,
            &signature,
            &wallet.public_key(),
            wallet.descriptor(),
        ));
        assert!(!verify_mldsa87_wallet_signature(
            b"tampered",
            &signature,
            &wallet.public_key(),
            wallet.descriptor(),
        ));
        assert!(!verify_mldsa87_wallet_signature(
            message,
            &[0_u8; ML_DSA_87_SIGNATURE_SIZE - 1],
            &wallet.public_key(),
            wallet.descriptor(),
        ));
    }

    #[test]
    fn wallet_exposes_valid_qrl_address_format() {
        let wallet =
            MlDsa87Wallet::from_seed(Seed::from_bytes(&[8_u8; crate::SEED_SIZE]).expect("seed"))
                .expect("wallet");
        assert!(is_valid_address(&wallet.address_string()));
    }
}
