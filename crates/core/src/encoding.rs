//! Human-friendly encoding of the Recovery Key: Crockford base32 with a checksum, in groups of four.

use crate::error::{Error, Result};
use crate::primitives::sha256;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Recovery key secret length in bytes (128 bits).
pub const RECOVERY_KEY_LEN: usize = 16;

/// Encodes 16 random bytes as `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (16 bytes + 1 checksum byte = 28 characters).
pub fn encode_recovery_key(secret: &[u8; RECOVERY_KEY_LEN]) -> String {
    let mut data = secret.to_vec();
    data.push(sha256(secret)[0]);
    let chars = base32_encode(&data);
    chars
        .as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).expect("ascii"))
        .collect::<Vec<_>>()
        .join("-")
}

/// Decodes a recovery key typed by a person: case, dashes and spaces don't matter; O reads as 0, I and L as 1.
pub fn decode_recovery_key(text: &str) -> Result<[u8; RECOVERY_KEY_LEN]> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    if cleaned.len() != 28 {
        return Err(Error::InvalidRecoveryKey);
    }
    let data = base32_decode(&cleaned).ok_or(Error::InvalidRecoveryKey)?;
    if data.len() < RECOVERY_KEY_LEN + 1 {
        return Err(Error::InvalidRecoveryKey);
    }
    let mut secret = [0u8; RECOVERY_KEY_LEN];
    secret.copy_from_slice(&data[..RECOVERY_KEY_LEN]);
    if sha256(&secret)[0] != data[RECOVERY_KEY_LEN] {
        return Err(Error::InvalidRecoveryKey);
    }
    Ok(secret)
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_forgiving_input() {
        let secret = [7u8; RECOVERY_KEY_LEN];
        let text = encode_recovery_key(&secret);
        assert_eq!(text.len(), 28 + 6);
        assert_eq!(decode_recovery_key(&text).unwrap(), secret);
        let sloppy = text.to_lowercase().replace('-', " ").replace('0', "o").replace('1', "l");
        assert_eq!(decode_recovery_key(&sloppy).unwrap(), secret);
    }

    #[test]
    fn typo_is_caught_by_the_checksum() {
        let secret = [42u8; RECOVERY_KEY_LEN];
        let mut text = encode_recovery_key(&secret).into_bytes();
        text[0] = if text[0] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            decode_recovery_key(core::str::from_utf8(&text).unwrap()),
            Err(Error::InvalidRecoveryKey)
        );
    }
}
