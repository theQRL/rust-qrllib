use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    SPHINCS_PLUS_256S_PUBLIC_KEY_SIZE,
    error::{QrllibError, Result},
    mldsa::ML_DSA_87_PUBLIC_KEY_SIZE,
};

/// Process-wide runtime override for the SPHINCS+ issuance gate.
/// Set by [`enable_experimental_sphincsplus_issuance_for_testing`].
/// (TOB-QRLLIB-4 — Rust-port mirror of the Go-side
/// `EnableExperimentalForTesting` helper.)
static SPHINCSPLUS_ISSUANCE_BYPASS: AtomicBool = AtomicBool::new(false);

/// Enable SPHINCS+/SLH-DSA wallet issuance for the lifetime of the
/// current process. Intended for **test harnesses, examples, and
/// developer experimentation** — production code that wants to enable
/// SPHINCS+ wallets should compile with the
/// `experimental-sphincsplus-issuance` Cargo feature instead, which
/// expresses the opt-in at the build-system level rather than via a
/// process-wide mutable flag.
///
/// Cargo integration-tests under `tests/` are compiled as downstream
/// consumers of `qrllib` — they do **not** inherit qrllib's `cfg(test)`
/// scope, so the `cfg(any(test, feature = "..."))` gate in
/// [`WalletType::is_issuable`] sees the test build as a production
/// build. The intended pattern for those tests is:
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
/// Once called, the bypass cannot be disabled within the same
/// process — this is intentional so a misuse cannot accidentally undo
/// a deliberate enable elsewhere in the process.
pub fn enable_experimental_sphincsplus_issuance_for_testing() {
    SPHINCSPLUS_ISSUANCE_BYPASS.store(true, Ordering::Relaxed);
}

/// Internal probe used by [`WalletType::is_issuable`].
fn sphincsplus_issuance_bypass_active() -> bool {
    SPHINCSPLUS_ISSUANCE_BYPASS.load(Ordering::Relaxed)
}

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
    pub fn is_issuable(self) -> bool {
        match self {
            Self::MlDsa87 => true,
            Self::SphincsPlus256s => {
                cfg!(any(test, feature = "experimental-sphincsplus-issuance"))
                    || sphincsplus_issuance_bypass_active()
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

#[cfg(test)]
mod tests {
    use super::WalletType;

    #[test]
    fn mldsa87_is_always_issuable() {
        // ML-DSA-87 is the primary recommended QRL v2 algorithm (FIPS 204)
        // and is issuable regardless of the SPHINCS+ experimental gate.
        assert!(WalletType::MlDsa87.is_issuable());
    }

    #[test]
    fn sphincsplus_is_issuable_in_crate_test_build() {
        // Exercises the `SphincsPlus256s` arm of `is_issuable`: the
        // `cfg!(any(test, feature = ...))` probe is `true` in an in-crate test
        // build, so issuance is permitted here even without the Cargo feature.
        assert!(WalletType::SphincsPlus256s.is_issuable());
    }

    #[test]
    fn both_wallet_types_are_verifiable() {
        // Existing addresses must remain verifiable for both wallet types
        // regardless of the issuance gate (TOB-QRLLIB-4).
        assert!(WalletType::MlDsa87.is_verifiable());
        assert!(WalletType::SphincsPlus256s.is_verifiable());
    }
}
