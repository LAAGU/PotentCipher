//! Thin wrappers over the audited primitives. Nothing here invents cryptography.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::keys::{KdfParams, Key32};

/// XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Salt length for Argon2id and file keys.
pub const SALT_LEN: usize = 16;

/// Random bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Encrypts with a fresh random nonce. Output: `nonce || ciphertext || tag`.
pub fn seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    seal_with_nonce(key, &random_bytes::<NONCE_LEN>(), plaintext, aad)
}

/// Encrypts with the given nonce (only for known-answer tests; real code uses [`seal`]).
pub fn seal_with_nonce(key: &Key32, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts `nonce || ciphertext || tag` made by [`seal`].
pub fn open(key: &Key32, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Format("sealed data too short"));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::Decrypt)
}

/// Wraps a key with a parent key.
pub fn wrap_key(parent: &Key32, child: &Key32, aad: &[u8]) -> Vec<u8> {
    seal(parent, child.as_bytes(), aad)
}

/// Unwraps a key made by [`wrap_key`].
pub fn unwrap_key(parent: &Key32, wrapped: &[u8], aad: &[u8]) -> Result<Key32> {
    let mut bytes = open(parent, wrapped, aad)?;
    let key = Key32::from_slice(&bytes);
    bytes.zeroize();
    key
}

/// HKDF-SHA256 to a 32-byte key.
pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let key = Key32::from_array(okm);
    okm.zeroize();
    key
}

/// Argon2id from a passphrase to a 32-byte key. Rejects parameters outside the allowed range.
pub fn argon2id(passphrase: &[u8], salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Key32> {
    params.validate()?;
    argon2id_unchecked(passphrase, salt, params)
}

/// Argon2id without the range check (known-answer tests use the RFC's tiny parameters).
pub(crate) fn argon2id_unchecked(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> Result<Key32> {
    let argon_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|_| Error::KdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; 32];
    argon.hash_password_into(passphrase, salt, &mut out).map_err(|_| Error::Kdf)?;
    let key = Key32::from_array(out);
    out.zeroize();
    Ok(key)
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Builds associated data from parts, so every ciphertext is bound to what it belongs to. Each part is
/// length-prefixed (u32 little-endian), so no two different part lists can produce the same bytes.
pub fn aad(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf(&ikm, &salt, &info);
        assert_eq!(
            hex::encode(okm.as_bytes()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn seal_open_round_trip_and_aad_binding() {
        let key = Key32::random();
        let sealed = seal(&key, b"hello", b"context-a");
        assert_eq!(open(&key, &sealed, b"context-a").unwrap(), b"hello");
        assert_eq!(open(&key, &sealed, b"context-b").err(), Some(Error::Decrypt));
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(open(&key, &flipped, b"context-a").err(), Some(Error::Decrypt));
    }

    #[test]
    fn aad_parts_cannot_collide() {
        assert_ne!(aad(&[b"ab", b"c"]), aad(&[b"a", b"bc"]));
    }
}
