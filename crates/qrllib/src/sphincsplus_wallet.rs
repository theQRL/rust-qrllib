use crate::{
    ADDRESS_SIZE,
    address::{format_address, unsafe_get_address},
    descriptor::Descriptor,
    error::{QrllibError, Result},
    mnemonic::{bin_to_mnemonic, mnemonic_to_bin},
    seed::{ExtendedSeed, Seed},
    sphincsplus::{
        SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
        SPHINCS_PLUS_256S_SECRET_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, SphincsPlus256s,
        verify_sphincsplus_signature,
    },
    wallet_type::WalletType,
};

#[derive(Clone, Debug)]
pub struct SphincsPlus256sWallet {
    descriptor: Descriptor,
    signer: SphincsPlus256s,
    seed: Seed,
}

pub fn verify_sphincsplus_wallet_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    descriptor: Descriptor,
) -> bool {
    if !matches!(descriptor.wallet_type(), Ok(WalletType::SphincsPlus256s)) {
        return false;
    }

    verify_sphincsplus_signature(message, signature, public_key)
}

impl SphincsPlus256sWallet {
    pub fn generate() -> Result<Self> {
        let seed = Seed::generate()?;
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: Seed) -> Result<Self> {
        let descriptor = Descriptor::sphincsplus256s();
        let derived_seed = seed.shake256(SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE);
        let mut core_seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
        core_seed.copy_from_slice(&derived_seed);
        let signer = SphincsPlus256s::from_seed(core_seed);
        Ok(Self { descriptor, signer, seed })
    }

    pub fn from_hex_seed(value: &str) -> Result<Self> {
        let seed = Seed::from_hex(value)?;
        Self::from_seed(seed)
    }

    pub fn from_extended_seed(extended_seed: ExtendedSeed) -> Result<Self> {
        let descriptor = extended_seed.descriptor();
        if descriptor.wallet_type()? != WalletType::SphincsPlus256s {
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

    pub fn public_key(&self) -> [u8; SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE] {
        self.signer.public_key_bytes()
    }

    pub fn secret_key(&self) -> [u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE] {
        self.signer.secret_key_bytes()
    }

    pub fn address(&self) -> [u8; ADDRESS_SIZE] {
        unsafe_get_address(&self.public_key(), self.descriptor)
    }

    pub fn address_string(&self) -> String {
        format_address(&self.address())
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE]> {
        self.signer.sign(message)
    }

    pub fn seal(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer.seal(message)
    }

    pub fn zeroize(&mut self) {
        self.seed.zeroize();
        self.signer.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{SphincsPlus256sWallet, verify_sphincsplus_wallet_signature};
    use crate::{
        address::is_valid_address,
        seed::{ExtendedSeed, Seed},
        sphincsplus::{
            SPHINCS_PLUS_256S_SIGNATURE_SIZE, sphincsplus_extract_signature, sphincsplus_open,
        },
    };

    #[test]
    fn deterministic_wallet_generation_matches_seed() {
        let seed = Seed::from_bytes(&[7_u8; crate::SEED_SIZE]).expect("seed");
        let wallet_a = SphincsPlus256sWallet::from_seed(seed.clone()).expect("wallet");
        let wallet_b = SphincsPlus256sWallet::from_seed(seed).expect("wallet");
        assert_eq!(wallet_a.public_key(), wallet_b.public_key());
        assert_eq!(wallet_a.address(), wallet_b.address());
        assert_eq!(wallet_a.descriptor(), wallet_b.descriptor());
    }

    #[test]
    fn wallet_known_vector_matches_go() {
        let wallet = SphincsPlus256sWallet::from_hex_extended_seed(
            "0x0000007b2c512b6fdc75bbd5adc5fe43393094c08b584d5789b642e83d946ff1dd48715c34ac02782071b44799f39f799ce47c",
        )
        .expect("wallet");
        assert_eq!(
            wallet.mnemonic().expect("mnemonic"),
            "aback aback lay share clever write jungle safer quaint grand eagle nail nephew angola frosty stead melody hale tower stuff inject brisk errant beside cuba scarf knit alpine rely land vine weed owing epic"
        );
        assert_eq!(
            wallet.address_string(),
            "Q2587cb706599afb8152e684511eee6c1c5650bb579c9bd530c5a661a5b79a64a68c96db3799b2c24f87c9cc057257096"
        );
        assert_eq!(
            hex::encode(wallet.public_key()),
            "881694158a04dc2f12fa58cac46d93ddac42f366c485f1e0086e0c4e88d3152fa18cb760e0f7439c38972c4b3fc2574eb951e3f3a88a4ca2607ccfee288efe27"
        );
    }

    #[test]
    fn extended_seed_and_mnemonic_round_trip() {
        let seed = Seed::from_bytes(&[9_u8; crate::SEED_SIZE]).expect("seed");
        let wallet = SphincsPlus256sWallet::from_seed(seed).expect("wallet");
        let extended_seed = wallet.extended_seed().expect("extended seed");
        let hex_seed = wallet.hex_seed().expect("hex seed");
        let mnemonic = wallet.mnemonic().expect("mnemonic");

        assert_eq!(
            SphincsPlus256sWallet::from_hex_extended_seed(&hex_seed)
                .expect("wallet from hex")
                .address(),
            wallet.address()
        );
        assert_eq!(
            SphincsPlus256sWallet::from_mnemonic(&mnemonic)
                .expect("wallet from mnemonic")
                .address(),
            wallet.address()
        );
        assert_eq!(
            ExtendedSeed::from_hex(&hex_seed).expect("extended seed from hex"),
            extended_seed
        );
    }

    #[test]
    fn wallet_signatures_verify() {
        let wallet = SphincsPlus256sWallet::from_seed(
            Seed::from_bytes(&[11_u8; crate::SEED_SIZE]).expect("seed"),
        )
        .expect("wallet");
        let message = b"browser-ready sphincs";
        let sealed = wallet.seal(message).expect("seal");
        assert_eq!(sphincsplus_open(&sealed, &wallet.public_key()).expect("open"), message);
        let signature = sphincsplus_extract_signature(&sealed).expect("signature");
        assert!(verify_sphincsplus_wallet_signature(
            message,
            signature,
            &wallet.public_key(),
            wallet.descriptor(),
        ));
        assert!(!verify_sphincsplus_wallet_signature(
            b"tampered",
            signature,
            &wallet.public_key(),
            wallet.descriptor(),
        ));
        assert!(!verify_sphincsplus_wallet_signature(
            message,
            &[0_u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE - 1],
            &wallet.public_key(),
            wallet.descriptor(),
        ));
    }

    #[test]
    fn wallet_exposes_valid_qrl_address_format_and_rejects_wrong_types() {
        let wallet = SphincsPlus256sWallet::from_seed(
            Seed::from_bytes(&[15_u8; crate::SEED_SIZE]).expect("seed"),
        )
        .expect("wallet");
        assert!(is_valid_address(&wallet.address_string()));

        let mldsa_seed = ExtendedSeed::new(crate::Descriptor::mldsa87(), &wallet.seed())
            .expect("mldsa extended seed");
        assert!(SphincsPlus256sWallet::from_extended_seed(mldsa_seed).is_err());
    }

    #[test]
    fn wallet_zeroize_clears_sensitive_state() {
        let mut wallet = SphincsPlus256sWallet::from_seed(
            Seed::from_bytes(&[21_u8; crate::SEED_SIZE]).expect("seed"),
        )
        .expect("wallet");
        wallet.zeroize();
        assert!(wallet.seed().as_bytes().iter().all(|byte| *byte == 0));
        assert!(wallet.secret_key().iter().all(|byte| *byte == 0));
    }
}
