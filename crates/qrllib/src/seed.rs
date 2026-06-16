use crate::{
    DESCRIPTOR_SIZE, EXTENDED_SEED_SIZE, SEED_SIZE,
    descriptor::Descriptor,
    error::{QrllibError, Result},
};
use sha2::Digest;
use shake::Shake256;
use zeroize::Zeroize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seed([u8; SEED_SIZE]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedSeed([u8; EXTENDED_SEED_SIZE]);

fn trim_hex_prefix(value: &str) -> &str {
    value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value)
}

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
        let bytes = hex::decode(trim_hex_prefix(value))?;
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

    pub fn shake256(&self, size: usize) -> Vec<u8> {
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = Shake256::default();
        hasher.update(self.0.as_slice());
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0_u8; size];
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
        let bytes = hex::decode(trim_hex_prefix(value))?;
        Self::from_bytes(&bytes)
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
