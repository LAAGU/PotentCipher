//! One-time codes for two-factor sign-in, for the 2FA field of "login" items: TOTP (RFC 6238) over HOTP (RFC 4226), with
//! the RustCrypto HMAC. The secret is the site's shared key in base32 (RFC 4648), as sites show it or put it in their
//! `otpauth://` QR codes. Codes are made on the device; the secret is stored only inside the encrypted item.

use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The hash a site's TOTP uses (almost always SHA-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the default.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// Decodes a base32 secret (RFC 4648 alphabet; spaces, dashes, padding and lower case are allowed, as sites write them).
pub fn totp_secret_from_base32(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in text.chars() {
        let value = match c.to_ascii_uppercase() {
            ' ' | '-' | '=' => continue,
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err(Error::Format("totp secret")),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if out.len() < 10 {
        return Err(Error::Format("totp secret too short"));
    }
    Ok(out)
}

fn hotp<M: Mac + hmac::digest::KeyInit>(secret: &[u8], counter: u64) -> Result<u32> {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(secret).map_err(|_| Error::InvalidKey)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation (RFC 4226 section 5.3).
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    Ok(u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]))
}

/// The code for `unix_seconds`: `digits` long (6 to 8), a new one every `period` seconds (15 to 120).
pub fn totp_code(secret: &[u8], unix_seconds: u64, period: u32, digits: u32, algorithm: TotpAlgorithm) -> Result<String> {
    if !(6..=8).contains(&digits) || !(15..=120).contains(&period) {
        return Err(Error::Format("totp settings"));
    }
    let counter = unix_seconds / u64::from(period);
    let value = match algorithm {
        TotpAlgorithm::Sha1 => hotp::<Hmac<sha1::Sha1>>(secret, counter)?,
        TotpAlgorithm::Sha256 => hotp::<Hmac<sha2::Sha256>>(secret, counter)?,
        TotpAlgorithm::Sha512 => hotp::<Hmac<sha2::Sha512>>(secret, counter)?,
    };
    let code = value % 10u32.pow(digits);
    Ok(format!("{code:0width$}", width = digits as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B: the ASCII seeds, 8 digits, 30-second steps.
    const SEED1: &[u8] = b"12345678901234567890";
    const SEED256: &[u8] = b"12345678901234567890123456789012";
    const SEED512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn matches_the_rfc_6238_vectors() {
        let cases: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (time, sha1, sha256, sha512) in cases {
            assert_eq!(totp_code(SEED1, *time, 30, 8, TotpAlgorithm::Sha1).unwrap(), *sha1);
            assert_eq!(totp_code(SEED256, *time, 30, 8, TotpAlgorithm::Sha256).unwrap(), *sha256);
            assert_eq!(totp_code(SEED512, *time, 30, 8, TotpAlgorithm::Sha512).unwrap(), *sha512);
        }
    }

    #[test]
    fn six_digits_keep_leading_zeros() {
        // RFC 4226 appendix D, count 0 = 755224 (time 0 with a 30 s step is counter 0).
        assert_eq!(totp_code(SEED1, 0, 30, 6, TotpAlgorithm::Sha1).unwrap(), "755224");
        assert_eq!(totp_code(SEED1, 1111111109, 30, 6, TotpAlgorithm::Sha1).unwrap(), "081804");
    }

    #[test]
    fn reads_base32_as_sites_write_it() {
        // "12345678901234567890" in base32.
        let secret = totp_secret_from_base32("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(secret.as_slice(), SEED1);
        assert!(totp_secret_from_base32("GEZDGNBVGY3TQOJQ====").is_ok());
        assert!(totp_secret_from_base32("not base32!").is_err());
        assert!(totp_secret_from_base32("GEZD").is_err());
    }

    #[test]
    fn refuses_odd_settings() {
        assert!(totp_code(SEED1, 0, 30, 4, TotpAlgorithm::Sha1).is_err());
        assert!(totp_code(SEED1, 0, 5, 6, TotpAlgorithm::Sha1).is_err());
    }
}
