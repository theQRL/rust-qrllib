use crate::{
    ADDRESS_SIZE,
    address::{format_address, unsafe_get_address},
    descriptor::Descriptor,
    error::{QrllibError, Result},
    mnemonic::{bin_to_mnemonic, mnemonic_to_bin},
    seed::{ExtendedSeed, Seed},
    signing_context::{SIGNING_CONTEXT_SIZE, signing_context},
    sphincsplus::{
        SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
        SPHINCS_PLUS_256S_SECRET_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, SphincsPlus256s,
        verify_sphincsplus_signature,
    },
    wallet_type::WalletType,
};
use zeroize::Zeroizing;

/// QRL V2.0 SPHINCS+-256s wallet.
///
/// Wraps the low-level [`SphincsPlus256s`] signer with QRL-specific
/// address derivation and a domain-separated **signing context**.
/// SPHINCS+ has no native context parameter, so the wallet prepends
/// the fixed-length [`signing_context`] bytes to the message before
/// signing — the resulting signature commits cryptographically to the
/// wallet's descriptor (and therefore to the address derived from it),
/// preventing a signature produced under descriptor `D1` from being
/// re-purposed as if it had been issued under any other descriptor
/// `D2`. (TOB-QRLLIB-3 framing.)
///
/// Callers do not supply the context themselves —
/// [`SphincsPlus256sWallet::sign`] prepends it from the wallet's own
/// descriptor, and [`verify_sphincsplus_wallet_signature`] prepends it
/// from the `descriptor` argument it receives.
#[derive(Clone, Debug)]
pub struct SphincsPlus256sWallet {
    descriptor: Descriptor,
    signer: SphincsPlus256s,
    seed: Seed,
}

/// Prepend the fixed-length signing context to the message so SPHINCS+
/// (which has no native ctx parameter) still commits to the descriptor in
/// its signed bytes. The prefix is compile-time constant length, so the
/// concatenation is canonically parseable and cannot collide with a
/// shifted-boundary forgery.
fn domain_separated_message(descriptor: Descriptor, message: &[u8]) -> Vec<u8> {
    let ctx = signing_context(descriptor);
    let mut out = Vec::with_capacity(SIGNING_CONTEXT_SIZE + message.len());
    out.extend_from_slice(&ctx);
    out.extend_from_slice(message);
    out
}

pub fn verify_sphincsplus_wallet_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    descriptor: Descriptor,
) -> bool {
    if !descriptor.is_valid()
        || !matches!(descriptor.wallet_type(), Ok(WalletType::SphincsPlus256s))
    {
        return false;
    }

    let domain_separated = domain_separated_message(descriptor, message);
    verify_sphincsplus_signature(&domain_separated, signature, public_key)
}

impl SphincsPlus256sWallet {
    /// Issuance-gate check shared by every wallet constructor.
    ///
    /// Returns `Err(QrllibError::WalletTypeNotIssuable(...))` when
    /// [`WalletType::SphincsPlus256s.is_issuable()`] is `false` —
    /// i.e. when the `experimental-sphincsplus-issuance` Cargo feature
    /// is not enabled and we are not in an in-crate test build.
    /// (TOB-QRLLIB-4.)
    ///
    /// Verification helpers and the raw [`SphincsPlus256s`] primitive
    /// remain unrestricted; this gate applies only to *new wallet
    /// creation* at the wallet layer.
    fn assert_issuable() -> Result<()> {
        // Coverage: in an in-crate test build `WalletType::SphincsPlus256s
        // .is_issuable()` is hard-wired `true` via `cfg!(any(test, ...))`, so the
        // negated guard can never fire here; the `WalletTypeNotIssuable` error is
        // reachable only from downstream (production) builds without the
        // `experimental-sphincsplus-issuance` feature.
        if !WalletType::SphincsPlus256s.is_issuable() {
            //coverage:ignore reason=defensively-unreachable
            return Err(QrllibError::WalletTypeNotIssuable(WalletType::SphincsPlus256s));
        }
        Ok(())
    }

    pub fn generate() -> Result<Self> {
        Self::assert_issuable()?;
        let seed = Seed::generate()?;
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: Seed) -> Result<Self> {
        Self::assert_issuable()?;
        let descriptor = Descriptor::sphincsplus256s();
        let derived_seed = seed.shake256(SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE);
        let mut core_seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
        core_seed.copy_from_slice(&derived_seed);
        let signer = SphincsPlus256s::from_seed(core_seed);
        Ok(Self { descriptor, signer, seed })
    }

    pub fn from_hex_seed(value: &str) -> Result<Self> {
        Self::assert_issuable()?;
        let seed = Seed::from_hex(value)?;
        Self::from_seed(seed)
    }

    pub fn from_extended_seed(extended_seed: ExtendedSeed) -> Result<Self> {
        Self::assert_issuable()?;
        let descriptor = extended_seed.descriptor();
        if descriptor.wallet_type()? != WalletType::SphincsPlus256s {
            return Err(QrllibError::InvalidDescriptor);
        }
        Self::from_seed(extended_seed.seed())
    }

    pub fn from_hex_extended_seed(value: &str) -> Result<Self> {
        Self::assert_issuable()?;
        let extended_seed = ExtendedSeed::from_hex(value)?;
        Self::from_extended_seed(extended_seed)
    }

    pub fn from_mnemonic(value: &str) -> Result<Self> {
        Self::assert_issuable()?;
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

    pub fn secret_key(&self) -> Zeroizing<[u8; SPHINCS_PLUS_256S_SECRET_KEY_SIZE]> {
        self.signer.secret_key_bytes()
    }

    pub fn address(&self) -> [u8; ADDRESS_SIZE] {
        unsafe_get_address(&self.public_key(), self.descriptor)
    }

    pub fn address_string(&self) -> String {
        format_address(&self.address())
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; SPHINCS_PLUS_256S_SIGNATURE_SIZE]> {
        self.signer.sign(&domain_separated_message(self.descriptor, message))
    }

    pub fn sign_attached(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer.sign_attached(&domain_separated_message(self.descriptor, message))
    }

    pub fn zeroize(&mut self) {
        self.seed.zeroize();
        self.signer.zeroize();
    }
}

impl Drop for SphincsPlus256sWallet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{SphincsPlus256sWallet, verify_sphincsplus_wallet_signature};
    use crate::{
        address::is_valid_address,
        seed::{ExtendedSeed, Seed},
        signing_context::signing_context,
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
            "Q2587cb706599afb8152e684511eee6c1c5650bb579c9bd530c5a661a5b79a64a68c96db3799b2c24f87c9cc05725709626cee5e4d951f3f64be825a50d67cf5c"
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
        let sealed = wallet.sign_attached(message).expect("sign_attached");
        // Wallet-level sign_attached signs over `ctx || message`, so low-level open
        // recovers the domain-separated bytes, not the raw message.
        let mut expected_opened = signing_context(wallet.descriptor()).to_vec();
        expected_opened.extend_from_slice(message);
        assert_eq!(sphincsplus_open(&sealed, &wallet.public_key()).expect("open"), expected_opened);
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
        assert!(
            !verify_sphincsplus_wallet_signature(
                message,
                signature,
                &wallet.public_key(),
                crate::Descriptor::new([crate::WalletType::MlDsa87.code(), 0, 0]),
            ),
            "wrong-type descriptor must not verify"
        );
        assert!(
            !verify_sphincsplus_wallet_signature(
                message,
                signature,
                &wallet.public_key(),
                crate::Descriptor::new([crate::WalletType::SphincsPlus256s.code(), 0x01, 0x00]),
            ),
            "non-canonical SPHINCS+ descriptor must not verify"
        );
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
