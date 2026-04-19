use std::{collections::HashMap, sync::LazyLock};

const WORDLIST_SOURCE: &str = include_str!("qrl_wordlist.txt");

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let words: Vec<_> = WORDLIST_SOURCE.lines().collect();
    assert_eq!(words.len(), 4096, "unexpected QRL wordlist size");
    words
});

static LOOKUP: LazyLock<HashMap<&'static str, usize>> =
    LazyLock::new(|| WORDS.iter().enumerate().map(|(idx, word)| (*word, idx)).collect());

pub(crate) fn words() -> &'static [&'static str] {
    WORDS.as_slice()
}

pub(crate) fn lookup(word: &str) -> Option<usize> {
    LOOKUP.get(word).copied()
}

#[cfg(test)]
mod tests {
    use super::{lookup, words};

    #[test]
    fn qrl_wordlist_is_loaded() {
        assert_eq!(words().len(), 4096);
        assert_eq!(words()[0], "aback");
        assert_eq!(lookup("aback"), Some(0));
        assert_eq!(lookup("zzzz"), None);
    }
}
