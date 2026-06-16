use crate::{
    ADDRESS_SIZE,
    descriptor::Descriptor,
    error::{QrllibError, Result},
};

// Compile-time invariant: a QRL address is the first ADDRESS_SIZE bytes of
// SHAKE256(descriptor || pk), and the checksum / format helpers below assume
// the address fits the project's 64-byte ceiling. Mirrors the runtime
// `AddressSize <= 64` guard in go-qrllib's `UnsafeGetAddress`, enforced here at
// compile time instead.
const _: () = assert!(ADDRESS_SIZE <= 64);

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

    let mut hasher = shake::Shake256::default();
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

const HEX_LEN: usize = ADDRESS_SIZE * 2;

/// EIP-55-style mixed-case checksum (QRL variant).
///
/// Identical algorithm across `@theqrl/wallet.js`, `go-qrllib`, and
/// `rust-qrllib` so the same address bytes produce the same checksummed
/// string in every implementation:
///
/// - **Hash:** SHAKE-256 of the UTF-8 bytes of the 128-character lowercase
///   hex (no `Q` prefix), with `dkLen = ADDRESS_SIZE`, giving exactly one
///   nibble per hex character.
/// - **Rule:** for each hex character, if it is a letter (`a`-`f`) and the
///   corresponding nibble of the hash is `>= 8`, uppercase it; otherwise
///   leave it lowercase.
/// - **`Q`:** always uppercase on output; not part of the checksum input.
///
/// Internal helper; assumes `lower_hex` is exactly `HEX_LEN` lowercase hex
/// characters.
fn checksummed_hex(lower_hex: &str) -> String {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    debug_assert_eq!(lower_hex.len(), HEX_LEN);
    debug_assert!(lower_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));

    let mut hasher = shake::Shake256::default();
    hasher.update(lower_hex.as_bytes());
    let mut hash = [0_u8; ADDRESS_SIZE];
    let mut reader = hasher.finalize_xof();
    reader.read(&mut hash);

    let mut out = String::with_capacity(lower_hex.len());
    for (i, ch) in lower_hex.bytes().enumerate() {
        if ch.is_ascii_lowercase() {
            // ch is 'a'..='f' (debug_assert above)
            let nibble = if i % 2 == 0 { hash[i / 2] >> 4 } else { hash[i / 2] & 0x0f };
            if nibble >= 8 {
                out.push((ch - (b'a' - b'A')) as char);
                continue;
            }
        }
        out.push(ch as char);
    }
    out
}

/// Returns the EIP-55-style mixed-case checksummed string form of `address`.
/// The returned string always uses uppercase `Q`. Use this in user-facing
/// displays where transcription-error detection is desirable;
/// [`format_address`] remains the canonical lowercase form for backward
/// compatibility with code that string-compares addresses.
pub fn to_checksum_address(address: &[u8; ADDRESS_SIZE]) -> String {
    let mut s = String::with_capacity(1 + HEX_LEN);
    s.push('Q');
    s.push_str(&checksummed_hex(&hex::encode(address)));
    s
}

/// Permissive address validator.
///
/// Accepts `"Q"` or `"q"` followed by 128 hex characters, where the hex body
/// is one of:
///
/// - all lowercase (case-uniform), or
/// - all uppercase (case-uniform), or
/// - mixed-case matching the EIP-55-style checksum (see [`checksummed_hex`]).
///
/// Mixed-case strings that do not match the checksum are rejected, mirroring
/// how Ethereum tooling treats EIP-55 addresses. Use
/// [`is_valid_checksum_address`] for the strict check that requires a
/// properly checksummed string.
pub fn is_valid_address(address: &str) -> bool {
    if address.len() != 1 + HEX_LEN {
        return false;
    }

    let Some((prefix, body)) = address.split_at_checked(1) else {
        return false;
    };
    if !matches!(prefix, "Q" | "q") {
        return false;
    }
    if !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }

    let lower = body.to_ascii_lowercase();
    if body == lower || body == body.to_ascii_uppercase() {
        return true;
    }
    // Mixed case — must satisfy the EIP-55-style checksum.
    body == checksummed_hex(&lower)
}

/// Strict address validator. Returns `true` only when `address` exactly
/// matches the canonical checksummed form produced by
/// [`to_checksum_address`]. The `Q` prefix must be uppercase and the hex
/// body must match character-for-character.
///
/// All-lowercase and all-uppercase forms that contain letters return
/// `false` even though they are otherwise valid (use [`is_valid_address`]
/// for the permissive check). Digit-only hex bodies have no checksum
/// information and return `true` when the rest of the format is valid.
pub fn is_valid_checksum_address(address: &str) -> bool {
    if address.len() != 1 + HEX_LEN {
        return false;
    }
    let Some((prefix, body)) = address.split_at_checked(1) else {
        return false;
    };
    if prefix != "Q" {
        return false;
    }
    if !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    body == checksummed_hex(&body.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{format_address, is_valid_address, is_valid_checksum_address, to_checksum_address};
    use crate::ADDRESS_SIZE;

    /// Cross-implementation parity vectors. Identical bytes must produce
    /// identical checksummed strings in `@theqrl/wallet.js`, `go-qrllib`,
    /// and `rust-qrllib`. If any of these strings diverge between the
    /// three implementations the EIP-55-style scheme is broken at the spec
    /// level; do not patch one side to fit the other without coordinating
    /// with the others.
    const PARITY_VECTORS: &[(&str, &str, &str)] = &[
        (
            "ML-DSA-87 wallet 1",
            "Qd5812f6cf4a0f645aa620cd57319a0ed649dd8f5519a9dde7770ae5b0e49e547985f35eb972a2a07041561aa39c65a3991478f9b1e6749e05277dcf58a9a8b72",
            "Qd5812F6Cf4a0f645aa620cd57319a0Ed649dd8f5519A9dde7770ae5b0E49e547985f35eB972A2a07041561aa39c65A3991478f9B1e6749e05277dcf58A9A8B72",
        ),
        (
            "ML-DSA-87 wallet 2",
            "Qbe95a82d87a6cb9c7ff4c64e0c15bb1dff20b1d77e6b571b28ad4736f2a2a3e5857e8c225d6d61399b15beef3b196936e490ed6e234374c4887cbbe86c13b1ba",
            "QBe95a82D87a6CB9c7Ff4C64e0C15BB1DFF20b1d77E6B571B28Ad4736f2a2A3E5857E8c225D6D61399B15BEeF3B196936E490ed6E234374C4887CBBe86C13b1BA",
        ),
        (
            "ML-DSA-87 wallet 3",
            "Q31f654037d4d7bce04e9522e4d346ab47a90686ef20a6c19916e68d3c77950f54babb7725ad48a3201c0acb74271e790730f9f39f9ce2e9ba1be9e41a763caf9",
            "Q31F654037D4d7BCE04E9522e4d346ab47a90686ef20A6c19916E68D3c77950f54bABB7725aD48A3201c0aCb74271E790730f9f39f9ce2e9Ba1BE9E41a763cAf9",
        ),
        (
            "ML-DSA-87 wallet 4",
            "Qafae844fa3be904799ccdb74e6f8b55d92f350df0b48605d1eaf4ffd63170d6c74a8db5f9f58309bec4cd18d500a8c6835ba53b886df50f962ec7dc98ec4e503",
            "QaFAE844Fa3bE904799cCdB74E6F8B55d92F350DF0B48605D1Eaf4ffd63170D6C74a8db5f9F58309bEc4cd18D500A8c6835BA53B886df50f962ec7DC98ec4e503",
        ),
        (
            "ML-DSA-87 wallet 5",
            "Q09a4e13536ec5ac05a1080522898bae3210d473a0a9e9a900bdc98361d1a9e8c2cc0652344bd35b0590b537a527cc68fa2893bc6100c1da713e5431eebafb150",
            "Q09A4E13536EC5aC05A1080522898bAE3210D473A0a9E9A900bDC98361D1A9e8C2cc0652344BD35B0590B537A527cc68fA2893bc6100c1dA713E5431EEbafb150",
        ),
        (
            "all-ff",
            "Qffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "QFFFfFFFFffFfffFfffFfFFfFFFFfffFFffFFfFfFFfFfFFfffFfFFFfFfFffFfFffffFfFFffFFFfFFFfFfffffFFFfffFffFfFfFFFFFfFFFFFFfFfFffFFFfffFfFF",
        ),
    ];

    fn decode_addr(lower: &str) -> [u8; ADDRESS_SIZE] {
        let body = hex::decode(&lower[1..]).expect("parity vector must be valid hex");
        let mut addr = [0_u8; ADDRESS_SIZE];
        addr.copy_from_slice(&body);
        addr
    }

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
    fn is_valid_address_accepts_all_uppercase_hex_body() {
        // 0xab → "ababab...ab" → uppercase → "ABABAB...AB" (case-uniform).
        let canonical = format_address(&[0xab; ADDRESS_SIZE]);
        let upper = format!("Q{}", canonical[1..].to_ascii_uppercase());
        assert!(is_valid_address(&upper), "all-uppercase hex body must validate");
    }

    #[test]
    fn is_valid_address_rejects_mixed_case_without_valid_checksum() {
        // Build a deliberately-broken mixed-case body that will not match
        // the SHAKE-256-derived case nibbles.
        let lower = format_address(&[0xab; ADDRESS_SIZE]);
        let mut chars: Vec<char> = lower[1..].chars().collect();
        for i in (0..chars.len()).step_by(2) {
            chars[i] = chars[i].to_ascii_uppercase();
        }
        let mixed: String = chars.into_iter().collect();
        assert!(
            !is_valid_address(&format!("Q{mixed}")),
            "mixed-case hex body without valid checksum must be rejected",
        );
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

    #[test]
    fn is_valid_address_rejects_multibyte_leading_char() {
        let mut candidate = String::from("é");
        candidate.push_str(&"0".repeat(1 + ADDRESS_SIZE * 2 - candidate.len()));
        assert_eq!(candidate.len(), 1 + ADDRESS_SIZE * 2);
        assert!(
            !is_valid_address(&candidate),
            "a correctly-sized string whose first char spans multiple bytes must not validate"
        );
    }

    #[test]
    fn to_checksum_address_matches_parity_vectors() {
        for (name, lower, expected) in PARITY_VECTORS {
            let addr = decode_addr(lower);
            let got = to_checksum_address(&addr);
            assert_eq!(&got, expected, "checksum mismatch for {name}");
        }
    }

    #[test]
    fn to_checksum_address_handles_all_zero() {
        let zeros = [0_u8; ADDRESS_SIZE];
        let expected: String = format!("Q{}", "0".repeat(ADDRESS_SIZE * 2));
        assert_eq!(to_checksum_address(&zeros), expected);
    }

    #[test]
    fn is_valid_checksum_address_accepts_canonical_form() {
        for (name, _lower, checksummed) in PARITY_VECTORS {
            assert!(
                is_valid_checksum_address(checksummed),
                "checksummed form should validate strictly: {name}",
            );
        }
    }

    #[test]
    fn is_valid_checksum_address_rejects_uniform_case_with_letters() {
        let v = PARITY_VECTORS[0];
        let upper = format!("Q{}", v.1[1..].to_ascii_uppercase());
        assert!(
            !is_valid_checksum_address(v.1),
            "all-lowercase with letters must fail strict check"
        );
        assert!(
            !is_valid_checksum_address(&upper),
            "all-uppercase with letters must fail strict check"
        );
    }

    #[test]
    fn is_valid_checksum_address_rejects_lowercase_q_prefix() {
        let v = PARITY_VECTORS[0];
        let lowered = format!("q{}", &v.2[1..]);
        assert!(!is_valid_checksum_address(&lowered));
    }

    #[test]
    fn is_valid_checksum_address_accepts_digit_only_hex() {
        let digit_only: String = format!("Q{}{}", "0123456789".repeat(12), "01234567",);
        assert_eq!(digit_only.len(), 1 + ADDRESS_SIZE * 2);
        assert!(is_valid_checksum_address(&digit_only));
    }

    #[test]
    fn is_valid_address_accepts_checksummed_and_uniform_forms() {
        for (name, lower, checksummed) in PARITY_VECTORS {
            assert!(is_valid_address(lower), "lowercase form rejected: {name}");
            assert!(is_valid_address(checksummed), "checksummed form rejected: {name}");
            let upper = format!("Q{}", lower[1..].to_ascii_uppercase());
            assert!(is_valid_address(&upper), "uppercase form rejected: {name}");
        }
    }

    #[test]
    fn is_valid_address_rejects_single_case_flip_in_checksum() {
        let v = PARITY_VECTORS[0];
        let mut bytes = v.2.as_bytes().to_vec();
        // Find the first hex letter and flip its case.
        let flip_idx = bytes
            .iter()
            .skip(1)
            .position(|b| b.is_ascii_alphabetic())
            .expect("parity vector must contain a hex letter")
            + 1;
        let c = bytes[flip_idx];
        bytes[flip_idx] =
            if c.is_ascii_lowercase() { c - (b'a' - b'A') } else { c + (b'a' - b'A') };
        let corrupted = String::from_utf8(bytes).unwrap();
        assert!(!is_valid_address(&corrupted), "case-flipped checksum must be rejected");
    }
}
