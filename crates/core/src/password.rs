//! Password and passphrase generators (uniform, from the OS CSPRNG) and the minimum passphrase rule.

use rand_core::{OsRng, RngCore};

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";
const CONSONANTS: &[u8] = b"bdfghjklmnprstvz";
const VOWELS: &[u8] = b"aeiou";

/// A uniformly random number below `n` (rejection sampling, no modulo bias).
fn below(n: u32) -> u32 {
    assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let value = OsRng.next_u32();
        if value < zone {
            return value % n;
        }
    }
}

/// A random password of `length` characters (8..=128), letters and digits, plus symbols if asked. Look-alike
/// characters (0/O, 1/l/I) are left out so it can be read and typed.
pub fn generate_password(length: usize, symbols: bool) -> String {
    let length = length.clamp(8, 128);
    let mut alphabet = String::new();
    alphabet.push_str(LOWER);
    alphabet.push_str(UPPER);
    alphabet.push_str(DIGITS);
    if symbols {
        alphabet.push_str(SYMBOLS);
    }
    let chars: Vec<char> = alphabet.chars().collect();
    (0..length).map(|_| chars[below(chars.len() as u32) as usize]).collect()
}

/// A passphrase of `words` (4..=12) made-up, pronounceable words of three syllables, joined by dashes, e.g.
/// `kovira-dusemo-...`. Each word carries about 19 bits, so five words are about 95 bits.
pub fn generate_passphrase(words: usize) -> String {
    let words = words.clamp(4, 12);
    (0..words)
        .map(|_| {
            (0..3)
                .flat_map(|_| {
                    [
                        CONSONANTS[below(CONSONANTS.len() as u32) as usize] as char,
                        VOWELS[below(VOWELS.len() as u32) as usize] as char,
                    ]
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// The floor the core enforces whatever the UI says: at least 12 characters. (The app also runs a strength estimate.)
pub fn passphrase_meets_minimum(passphrase: &str) -> bool {
    passphrase.chars().count() >= 12
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_has_the_length_and_alphabet() {
        let p = generate_password(24, false);
        assert_eq!(p.chars().count(), 24);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(generate_password(2, true).chars().count(), 8);
    }

    #[test]
    fn passphrase_shape() {
        let p = generate_passphrase(5);
        assert_eq!(p.split('-').count(), 5);
        assert!(p.split('-').all(|w| w.len() == 6));
        assert!(passphrase_meets_minimum(&p));
        assert!(!passphrase_meets_minimum("short one"));
    }
}
