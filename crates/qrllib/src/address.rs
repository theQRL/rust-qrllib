use crate::{
    ADDRESS_SIZE,
    descriptor::Descriptor,
    error::{QrllibError, Result},
};

/// Derive an address from `public_key` and `descriptor` **without** validating
/// that the public-key length matches the descriptor's declared wallet type.
///
/// This is a lower-level primitive intended for internal callers that have
/// already validated the public key shape (see the wallet implementations in
/// [`crate::wallet`] and [`crate::sphincsplus_wallet`]). External callers
/// should almost always use [`get_address`] instead; that entry point performs
/// the shape check and returns an error on mismatch. For that reason the
/// symbol is reachable only via the module path (`qrllib::address::unsafe_get_address`)
/// and is not re-exported from the crate root.
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
    let descriptor = descriptor.validate()?;
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
    if address.len() != 1 + ADDRESS_SIZE * 2 {
        return false;
    }

    let Some((prefix, rest)) = address.split_at_checked(1) else {
        return false;
    };
    if !matches!(prefix, "Q" | "q") {
        return false;
    }

    hex::decode(rest).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{format_address, is_valid_address};
    use crate::ADDRESS_SIZE;

    #[test]
    fn is_valid_address_accepts_canonical_uppercase_prefix() {
        let canonical = format_address(&[0x5a; ADDRESS_SIZE]);
        assert!(canonical.starts_with('Q'));
        assert!(is_valid_address(&canonical));
    }

    #[test]
    fn is_valid_address_accepts_lowercase_q_prefix() {
        let canonical = format_address(&[0x5a; ADDRESS_SIZE]);
        let lowercased = format!("q{}", &canonical[1..]);
        assert!(is_valid_address(&lowercased), "address with lowercase q prefix must validate");
    }

    #[test]
    fn is_valid_address_accepts_mixed_case_hex_body() {
        let canonical = format_address(&[0xab; ADDRESS_SIZE]);
        let mixed = format!("Q{}", canonical[1..].to_ascii_uppercase());
        assert!(is_valid_address(&mixed), "mixed-case hex body must validate");
    }

    #[test]
    fn is_valid_address_rejects_wrong_prefix() {
        let canonical = format_address(&[0xab; ADDRESS_SIZE]);
        let wrong_prefix = format!("X{}", &canonical[1..]);
        assert!(!is_valid_address(&wrong_prefix));
    }

    #[test]
    fn is_valid_address_rejects_wrong_length() {
        let canonical = format_address(&[0xab; ADDRESS_SIZE]);
        assert!(!is_valid_address(&canonical[..canonical.len() - 1]));
        assert!(!is_valid_address(&format!("{canonical}0")));
    }

    #[test]
    fn is_valid_address_rejects_non_hex_body() {
        let body = "z".repeat(ADDRESS_SIZE * 2);
        assert!(!is_valid_address(&format!("Q{body}")));
    }
}
