use crate::{
    ADDRESS_SIZE,
    descriptor::Descriptor,
    error::{QrllibError, Result},
};

pub fn unsafe_get_address(public_key: &[u8], descriptor: Descriptor) -> [u8; ADDRESS_SIZE] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut hasher = sha3::Shake256::default();
    hasher.update(descriptor.as_ref());
    hasher.update(public_key);

    let mut address = [0_u8; ADDRESS_SIZE];
    let mut reader = hasher.finalize_xof();
    reader.read(&mut address);
    address
}

pub fn get_address(public_key: &[u8], descriptor: Descriptor) -> Result<[u8; ADDRESS_SIZE]> {
    let wallet_type = descriptor.wallet_type()?;
    let expected_size = wallet_type.expected_public_key_size();

    if public_key.len() != expected_size {
        return Err(QrllibError::InvalidPublicKeySize {
            wallet_type,
            actual: public_key.len(),
            expected: expected_size,
        });
    }

    Ok(unsafe_get_address(public_key, descriptor))
}

pub fn format_address(address: &[u8; ADDRESS_SIZE]) -> String {
    format!("Q{}", hex::encode(address))
}

pub fn is_valid_address(address: &str) -> bool {
    address.len() == 1 + ADDRESS_SIZE * 2
        && address.starts_with('Q')
        && hex::decode(&address[1..]).is_ok()
}
