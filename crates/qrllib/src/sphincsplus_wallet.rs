use crate::{
    ADDRESS_SIZE,
    address::{format_address, unsafe_get_address},
    descriptor::Descriptor,
    error::{QrllibError, Result},
    mnemonic::{bin_to_mnemonic, mnemonic_to_bin},
    seed::{ExtendedSeed, Seed, trim_hex_prefix},
    signing_context::{SIGNING_CONTEXT_SIZE, signing_context},
    sphincsplus::{
        SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE, SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
        SPHINCS_PLUS_256S_SECRET_KEY_SIZE, SPHINCS_PLUS_256S_SIGNATURE_SIZE, SphincsPlus256s,
        verify_sphincsplus_signature,
    },
    wallet_type::WalletType,
};
use core::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, Zeroizing};

/// Process-wide runtime override for the SPHINCS+ wallet gate.
/// Set by [`enable_experimental_sphincsplus_issuance_for_testing`].
static SPHINCSPLUS_EXPERIMENTAL: AtomicBool = AtomicBool::new(false);

/// Enable the SPHINCS+/SLH-DSA wallet path for the lifetime of the
/// current process. Intended for **test harnesses and developer
/// experimentation**.
///
/// # Availability (CIPH-RUSTQRL-6 / go-qrllib CIPH-QRLLIB-2)
///
/// This helper is compiled **only** into debug builds
/// (`debug_assertions`) or builds that enable the
/// `experimental-sphincsplus-issuance` Cargo feature, so it is absent
/// from a default release build and production code cannot link it.
/// It mirrors Go's `wallet/sphincsplus_256s.EnableExperimentalForTesting`,
/// which panics outside a `go test` binary for the same reason.
///
/// Cargo integration tests under `tests/` are downstream consumers that
/// do **not** inherit qrllib's `cfg(test)` scope, so they must call this
/// before constructing or verifying SPHINCS+ wallets:
///
/// ```ignore
/// use qrllib::enable_experimental_sphincsplus_issuance_for_testing;
///
/// #[test]
/// fn my_sphincs_wallet_test() {
///     enable_experimental_sphincsplus_issuance_for_testing();
///     // ... now SphincsPlus256sWallet::generate() etc. work.
/// }
/// ```
///
/// Once called, the override cannot be disabled within the same process —
/// intentionally, so a misuse cannot accidentally undo a deliberate
/// enable elsewhere.
///
/// The supported activation path for SLH-DSA is a change to
/// [`WalletType::is_issuable`] / [`WalletType::is_verifiable`], not this
/// helper. Wallets and signatures created through it may not be
/// compatible with eventual activation, which may carry parameter-set or
/// layout differences.
#[cfg(any(debug_assertions, feature = "experimental-sphincsplus-issuance"))]
pub fn enable_experimental_sphincsplus_issuance_for_testing() {
    SPHINCSPLUS_EXPERIMENTAL.store(true, Ordering::Relaxed);
}

/// The package-local experimental opt-in, layered on top of the
/// type-level gates exactly as Go's `experimental` package variable is.
fn experimental() -> bool {
    cfg!(any(test, feature = "experimental-sphincsplus-issuance"))
        || SPHINCSPLUS_EXPERIMENTAL.load(Ordering::Relaxed)
}

/// Whether new SPHINCS+-256s wallets may be constructed today: the
/// type-level gate, or the experimental opt-in. Parity with Go's
/// `wallet/sphincsplus_256s.issuable`.
fn issuable() -> bool {
    experimental() || WalletType::SphincsPlus256s.is_issuable()
}

/// Whether SPHINCS+-256s signatures may be verified today. Verification-side
/// mirror of [`issuable`], and of Go's `wallet/sphincsplus_256s.verifiable`.
fn verifiable() -> bool {
    experimental() || WalletType::SphincsPlus256s.is_verifiable()
}

/// Package-local descriptor validity for the experimental SPHINCS+ path.
///
/// `SPHINCSPLUS_256S` is deliberately rejected by
/// [`Descriptor::is_valid`], so this module cannot use the common check
/// and applies its own — the same split Go draws between
/// `descriptor.Descriptor.IsValid` and the package-local
/// `sphincsplus_256s.Descriptor.IsValid`. Bytes 1 and 2 carry no defined
/// semantics today and must be zero.
fn descriptor_is_valid(descriptor: Descriptor) -> bool {
    descriptor.type_code() == WalletType::SphincsPlus256s.code() && descriptor.metadata() == [0, 0]
}

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
#[derive(Clone)]
pub struct SphincsPlus256sWallet {
    descriptor: Descriptor,
    signer: SphincsPlus256s,
    seed: Seed,
}

// Redacting `Debug` (CIPH-RUSTQRL-1): the wallet owns the seed and signer
// secret key. The descriptor is public and safe to surface.
impl core::fmt::Debug for SphincsPlus256sWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SphincsPlus256sWallet")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
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
    // Default builds refuse every SPHINCS+ signature, matching go-qrllib's
    // `wallet/sphincsplus_256s.Verify`. Unreachable under test, where
    // `experimental()` is always true.
    if !verifiable() {
        //coverage:ignore reason=defensively-unreachable
        return false;
    }
    if !descriptor_is_valid(descriptor) {
        return false;
    }

    let domain_separated = domain_separated_message(descriptor, message);
    verify_sphincsplus_signature(&domain_separated, signature, public_key)
}

impl SphincsPlus256sWallet {
    /// Issuance-gate check shared by every wallet constructor.
    ///
    /// Returns `Err(QrllibError::WalletTypeNotIssuable(...))` when
    /// [`issuable`] is `false` (TOB-QRLLIB-4).
    ///
    /// The raw [`SphincsPlus256s`] primitive remains unrestricted; this
    /// gate applies only to *new wallet creation* at the wallet layer.
    fn assert_issuable() -> Result<()> {
        // Unreachable under test, where `experimental()` is always true; the
        // error is reachable only from default downstream builds.
        if !issuable() {
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
        // CIPH-RUSTQRL-2: `derived_seed` is the full SPHINCS+ crypto seed
        // (`Seed::shake256` now returns a `Zeroizing<Vec<u8>>`); wipe the
        // fixed-size `core_seed` copy once the signer has been constructed.
        let derived_seed = seed.shake256(SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE);
        let mut core_seed = [0_u8; SPHINCS_PLUS_256S_CRYPTO_SEED_SIZE];
        core_seed.copy_from_slice(&derived_seed);
        let signer = SphincsPlus256s::from_seed(core_seed);
        core_seed.zeroize();
        Ok(Self { descriptor, signer, seed })
    }

    pub fn from_hex_seed(value: &str) -> Result<Self> {
        Self::assert_issuable()?;
        let seed = Seed::from_hex(value)?;
        Self::from_seed(seed)
    }

    pub fn from_extended_seed(extended_seed: ExtendedSeed) -> Result<Self> {
        Self::assert_issuable()?;
        if !descriptor_is_valid(extended_seed.descriptor()) {
            return Err(QrllibError::InvalidDescriptor);
        }
        Self::from_seed(extended_seed.seed())
    }

    pub fn from_hex_extended_seed(value: &str) -> Result<Self> {
        Self::assert_issuable()?;
        // `ExtendedSeed::from_hex` applies the production descriptor policy,
        // which rejects SPHINCS+. Decode raw and let `from_extended_seed`
        // apply this module's own descriptor rules instead — the same shape
        // as Go's `NewWalletFromHexExtendedSeed`.
        let bytes = Zeroizing::new(
            hex::decode(trim_hex_prefix(value)).map_err(|_| QrllibError::InvalidHexSeed)?,
        );
        let extended_seed = ExtendedSeed::from_bytes_unchecked(&bytes)?;
        Self::from_extended_seed(extended_seed)
    }

    pub fn from_mnemonic(value: &str) -> Result<Self> {
        Self::assert_issuable()?;
        let bytes = mnemonic_to_bin(value)?;
        let extended_seed = ExtendedSeed::from_bytes_unchecked(&bytes)?;
        Self::from_extended_seed(extended_seed)
    }

    pub fn seed(&self) -> Seed {
        self.seed.clone()
    }

    /// SPHINCSPLUS_256S is intentionally not a valid common wallet
    /// descriptor while the wallet path is gated (TOB-QRLLIB-4), so this
    /// module cannot use [`ExtendedSeed::new`], which enforces the
    /// production descriptor policy. Assemble the byte layout directly,
    /// exactly as Go's `wallet/sphincsplus_256s.GetExtendedSeed` does.
    pub fn extended_seed(&self) -> Result<ExtendedSeed> {
        if !descriptor_is_valid(self.descriptor) {
            //coverage:ignore reason=defensively-unreachable
            return Err(QrllibError::InvalidDescriptor);
        }
        Ok(ExtendedSeed::from_parts_unchecked(self.descriptor, &self.seed))
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
        // The common `ExtendedSeed` constructors enforce the production
        // descriptor policy, which rejects SPHINCS+ (TOB-QRLLIB-4, parity
        // with go-qrllib). This module lays the bytes out itself, so check
        // the round trip against the wallet's own hex rendering instead.
        assert!(
            ExtendedSeed::from_hex(&hex_seed).is_err(),
            "SPHINCS+ extended seed must not parse through the common policy check"
        );
        assert_eq!(extended_seed.to_hex_prefixed(), hex_seed);
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

        // A SPHINCS+ descriptor carrying non-zero metadata bytes is not a
        // well-formed descriptor for this module either.
        let non_canonical = ExtendedSeed::from_parts_unchecked(
            crate::Descriptor::new([crate::WalletType::SphincsPlus256s.code(), 0x01, 0x00]),
            &wallet.seed(),
        );
        assert!(SphincsPlus256sWallet::from_extended_seed(non_canonical).is_err());
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
