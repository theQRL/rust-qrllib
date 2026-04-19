use crate::{
    error::{QrllibError, Result},
    wordlist,
};

pub fn bin_to_mnemonic(input: &[u8]) -> Result<String> {
    if !input.len().is_multiple_of(3) {
        return Err(QrllibError::InvalidMnemonicByteCount);
    }

    let words = wordlist::words();
    let mut output = Vec::with_capacity(input.len() * 2 / 3);

    for nibble in (0..input.len() * 2).step_by(3) {
        let p = nibble >> 1;
        let b1 = u32::from(input[p]);
        let b2 = input.get(p + 1).copied().map_or(0, u32::from);
        let index = if nibble % 2 == 0 { (b1 << 4) + (b2 >> 4) } else { ((b1 & 0x0f) << 8) + b2 };
        output.push(words[index as usize]);
    }

    Ok(output.join(" "))
}

pub fn mnemonic_to_bin(mnemonic: &str) -> Result<Vec<u8>> {
    let mnemonic_words: Vec<_> = mnemonic.split(' ').collect();
    if mnemonic_words.len() % 2 != 0 {
        return Err(QrllibError::InvalidMnemonicWordCount(mnemonic_words.len()));
    }

    let mut result = vec![0_u8; mnemonic_words.len() * 15 / 10];
    let mut current = 0_usize;
    let mut buffering = 0_usize;
    let mut result_index = 0_usize;

    for word in mnemonic_words {
        let value = wordlist::lookup(word).ok_or(QrllibError::InvalidMnemonicWord)?;

        buffering += 3;
        current = (current << 12) + value;

        while buffering > 2 {
            let shift = 4 * (buffering - 2);
            let mask = (1 << shift) - 1;
            let tmp = current >> shift;
            buffering -= 2;
            current &= mask;
            result[result_index] = tmp as u8;
            result_index += 1;
        }
    }

    if buffering > 0 && result_index < result.len() {
        result[result_index] = (current & 0xff) as u8;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{bin_to_mnemonic, mnemonic_to_bin};

    #[test]
    fn mnemonic_round_trip() {
        let input = [0_u8; 51];
        let mnemonic = bin_to_mnemonic(&input).expect("mnemonic");
        let restored = mnemonic_to_bin(&mnemonic).expect("restore");
        assert_eq!(restored, input);
    }

    #[test]
    fn mnemonic_rejects_invalid_inputs() {
        assert!(bin_to_mnemonic(&[0_u8; 1]).is_err());
        assert!(mnemonic_to_bin("aback").is_err());
        assert!(mnemonic_to_bin("aback not-a-word").is_err());
    }
}
