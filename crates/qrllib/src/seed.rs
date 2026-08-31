use crate::{
    DESCRIPTOR_SIZE, EXTENDED_SEED_SIZE, SEED_SIZE,
    descriptor::Descriptor,
    error::{QrllibError, Result},
};
use sha2::Digest;
use shake::Shake256;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct Seed([u8; SEED_SIZE]);

#[derive(Clone)]
pub struct ExtendedSeed([u8; EXTENDED_SEED_SIZE]);

pub(crate) fn trim_hex_prefix(value: &str) -> &str {
    value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value)
}

/// Constant-time byte-slice equality (CIPH-RUSTQRL-9). Compares in time
/// independent of the position of the first differing byte, so equality checks
/// on secret seed material do not leak a prefix-match length via timing. The
/// slices always have equal (compile-time-fixed) length here.
///
/// The accumulated `diff` is passed through `core::hint::black_box` before the
/// comparison so the optimizer cannot prove a relationship between the inputs
/// and short-circuit the accumulation loop into an early-exit compare — the same
/// barrier used for the ML-KEM constant-time select (CIPH-RUSTQRL-7).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

// Redacting `Debug` (CIPH-RUSTQRL-1): the wrapped bytes are secret seed
// material and must never reach a log line via `{:?}`.
impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Seed").finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ExtendedSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedSeed").finish_non_exhaustive()
    }
}

// Constant-time equality on secret material (CIPH-RUSTQRL-9) in place of the
// short-circuiting derived `PartialEq`.
impl PartialEq for Seed {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for Seed {}

impl PartialEq for ExtendedSeed {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for ExtendedSeed {}

impl Seed {
    pub fn generate() -> Result<Self> {
        let mut seed = [0_u8; SEED_SIZE];
        getrandom::getrandom(&mut seed)?;
        Ok(Self(seed))
    }

    pub fn from_bytes(seed_bytes: &[u8]) -> Result<Self> {
        if seed_bytes.len() != SEED_SIZE {
            return Err(QrllibError::InvalidSeedSize(seed_bytes.len(), SEED_SIZE));
        }

        let mut seed = [0_u8; SEED_SIZE];
        seed.copy_from_slice(seed_bytes);
        Ok(Self(seed))
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        // Map the decode failure to the sanitized sentinel rather than
        // propagating `hex::FromHexError`, whose Display echoes the offending
        // input character — the input is secret seed material (CIPH-RUSTQRL-3).
        // Wrap the decoded buffer in `Zeroizing` so the transient secret seed is
        // wiped on drop (CIPH-RUSTQRL-2 / go CIPH-QRLLIB-4).
        let bytes = Zeroizing::new(
            hex::decode(trim_hex_prefix(value)).map_err(|_| QrllibError::InvalidHexSeed)?,
        );
        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SEED_SIZE] {
        &self.0
    }

    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn sha256(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.0);
        hasher.finalize().into()
    }

    /// Returns a zeroizing SHAKE-256 expansion of the seed. The output is
    /// secret-derived key material (CIPH-RUSTQRL-2), so it drop-clears on
    /// scope exit rather than being left in a plain `Vec`.
    pub fn shake256(&self, size: usize) -> Zeroizing<Vec<u8>> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = Shake256::default();
        hasher.update(self.0.as_slice());
        let mut reader = hasher.finalize_xof();
        let mut output = Zeroizing::new(vec![0_u8; size]);
        reader.read(&mut output);
        output
    }

    pub fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ExtendedSeed {
    pub fn new(descriptor: Descriptor, seed: &Seed) -> Result<Self> {
        descriptor.validate()?;

        let mut bytes = [0_u8; EXTENDED_SEED_SIZE];
        bytes[..DESCRIPTOR_SIZE].copy_from_slice(descriptor.as_ref());
        bytes[DESCRIPTOR_SIZE..].copy_from_slice(seed.as_bytes());
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EXTENDED_SEED_SIZE {
            return Err(QrllibError::InvalidExtendedSeedSize(bytes.len(), EXTENDED_SEED_SIZE));
        }

        let descriptor = Descriptor::from_bytes(&bytes[..DESCRIPTOR_SIZE])?;
        descriptor.validate()?;

        let mut extended = [0_u8; EXTENDED_SEED_SIZE];
        extended.copy_from_slice(bytes);
        Ok(Self(extended))
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        // Sanitized sentinel rather than the echoing `hex::FromHexError` — the
        // extended seed embeds secret seed material (CIPH-RUSTQRL-3). The decoded
        // buffer is wiped on drop (CIPH-RUSTQRL-2 / go CIPH-QRLLIB-4).
        let bytes = Zeroizing::new(
            hex::decode(trim_hex_prefix(value)).map_err(|_| QrllibError::InvalidHexSeed)?,
        );
        Self::from_bytes(&bytes)
    }

    /// Assemble an extended seed **without** the production descriptor
    /// policy check applied by [`Self::new`].
    ///
    /// Parity with go-qrllib: `SPHINCSPLUS_256S` is intentionally not a
    /// valid common wallet descriptor while the wallet path is gated
    /// (TOB-QRLLIB-4), so `wallet/sphincsplus_256s` cannot use
    /// `common.NewExtendedSeed` and lays out the bytes by hand instead.
    /// This is the Rust equivalent, and is crate-internal for the same
    /// reason: it must not become a way for callers to route around
    /// [`Descriptor::is_valid`].
    pub(crate) fn from_parts_unchecked(descriptor: Descriptor, seed: &Seed) -> Self {
        let mut bytes = [0_u8; EXTENDED_SEED_SIZE];
        bytes[..DESCRIPTOR_SIZE].copy_from_slice(descriptor.as_ref());
        bytes[DESCRIPTOR_SIZE..].copy_from_slice(seed.as_bytes());
        Self(bytes)
    }

    /// Length-checked byte import that skips the descriptor policy check,
    /// mirroring the raw `copy(extendedSeed[:], bin)` that Go's
    /// `wallet/sphincsplus_256s` constructors perform before validating
    /// the descriptor against their own package-local rules.
    pub(crate) fn from_bytes_unchecked(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EXTENDED_SEED_SIZE {
            return Err(QrllibError::InvalidExtendedSeedSize(bytes.len(), EXTENDED_SEED_SIZE));
        }

        let mut extended = [0_u8; EXTENDED_SEED_SIZE];
        extended.copy_from_slice(bytes);
        Ok(Self(extended))
    }

    pub fn descriptor(&self) -> Descriptor {
        let mut descriptor = [0_u8; DESCRIPTOR_SIZE];
        descriptor.copy_from_slice(&self.0[..DESCRIPTOR_SIZE]);
        Descriptor::new(descriptor)
    }

    pub fn seed(&self) -> Seed {
        let mut seed = [0_u8; SEED_SIZE];
        seed.copy_from_slice(&self.0[DESCRIPTOR_SIZE..]);
        Seed(seed)
    }

    pub fn as_bytes(&self) -> &[u8; EXTENDED_SEED_SIZE] {
        &self.0
    }

    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ExtendedSeed {
    fn drop(&mut self) {
        self.zeroize();
    }
}
