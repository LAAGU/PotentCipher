//! Secret links (docs/02-key-sharing.md, "B"; format in docs/01-encryption-design.md, "Secret links"). The sender's device
//! makes a random 32-byte link key, encrypts the secret with it and uploads only the result; the key travels in the link
//! after `#`, which browsers never send to a server. An optional passphrase is a second factor: the content key then also
//! needs Argon2id of that passphrase, so the link alone opens nothing.
//!
//! Blob: `version (1) | flags (1) | [salt (16) | memory KiB, iterations, lanes (u32 LE each)] | nonce | ciphertext | tag`.
//! Content key: HKDF-SHA256(link key [|| Argon2id(passphrase, salt)], info "pc-link-v1"). The header and the link's id are
//! bound in the associated data, so a server can't swap blobs between links or strip the passphrase flag.

use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::keys::{KdfParams, Key32};
use crate::primitives::{aad, argon2id, hkdf, open, random_bytes, seal, SALT_LEN};

const VERSION: u8 = 1;
const FLAG_PASSPHRASE: u8 = 1;
const INFO: &[u8] = b"pc-link-v1";
const HEADER_PLAIN: usize = 2;
const HEADER_PASS: usize = 2 + SALT_LEN + 12;

fn content_key(link_key: &Key32, passphrase_key: Option<&Key32>) -> Key32 {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(link_key.as_bytes());
    if let Some(extra) = passphrase_key {
        ikm.extend_from_slice(extra.as_bytes());
    }
    let key = hkdf(&ikm, b"", INFO);
    ikm.zeroize();
    key
}

fn associated(link_id: &str, header: &[u8]) -> Vec<u8> {
    aad(&[INFO, link_id.as_bytes(), header])
}

/// Encrypts a secret for a link: the new link key (for the `#` part) and the blob to upload.
pub fn link_seal(link_id: &str, plaintext: &[u8], passphrase: Option<&[u8]>, kdf: &KdfParams) -> Result<(Key32, Vec<u8>)> {
    let link_key = Key32::random();
    let mut header = vec![VERSION, 0];
    let passphrase_key = match passphrase {
        Some(words) => {
            let salt = random_bytes::<SALT_LEN>();
            let key = argon2id(words, &salt, kdf)?;
            header[1] = FLAG_PASSPHRASE;
            header.extend_from_slice(&salt);
            for value in [kdf.memory_kib, kdf.iterations, kdf.parallelism] {
                header.extend_from_slice(&value.to_le_bytes());
            }
            Some(key)
        }
        None => None,
    };
    let key = content_key(&link_key, passphrase_key.as_ref());
    let mut blob = header.clone();
    blob.extend_from_slice(&seal(&key, plaintext, &associated(link_id, &header)));
    Ok((link_key, blob))
}

/// Whether the blob also needs the link's passphrase.
pub fn link_needs_passphrase(blob: &[u8]) -> Result<bool> {
    match blob {
        [VERSION, 0, ..] if blob.len() > HEADER_PLAIN => Ok(false),
        [VERSION, FLAG_PASSPHRASE, ..] if blob.len() > HEADER_PASS => Ok(true),
        _ => Err(Error::Format("secret link")),
    }
}

/// Opens a link's blob with the key from the link (and its passphrase when it has one).
pub fn link_open(link_id: &str, link_key: &[u8], blob: &[u8], passphrase: Option<&[u8]>) -> Result<Vec<u8>> {
    let link_key = Key32::from_slice(link_key)?;
    let (header, sealed, passphrase_key) = if link_needs_passphrase(blob)? {
        let words = passphrase.ok_or(Error::Decrypt)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&blob[2..2 + SALT_LEN]);
        let number = |at: usize| u32::from_le_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]]);
        let at = 2 + SALT_LEN;
        let kdf = KdfParams { memory_kib: number(at), iterations: number(at + 4), parallelism: number(at + 8) };
        // A link can't make this device spend more (or protect with less) than the allowed range.
        let key = argon2id(words, &salt, &kdf)?;
        (&blob[..HEADER_PASS], &blob[HEADER_PASS..], Some(key))
    } else {
        (&blob[..HEADER_PLAIN], &blob[HEADER_PLAIN..], None)
    };
    let key = content_key(&link_key, passphrase_key.as_ref());
    open(&key, sealed, &associated(link_id, header))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIGHT: KdfParams = KdfParams { memory_kib: KdfParams::MIN_MEMORY_KIB, iterations: 2, parallelism: 1 };

    #[test]
    fn opens_with_the_link_key_only() {
        let (key, blob) = link_seal("link-1", b"hunter2", None, &LIGHT).unwrap();
        assert!(!link_needs_passphrase(&blob).unwrap());
        assert_eq!(link_open("link-1", key.as_bytes(), &blob, None).unwrap(), b"hunter2");
        assert_eq!(link_open("link-1", Key32::random().as_bytes(), &blob, None).err(), Some(Error::Decrypt));
    }

    #[test]
    fn is_bound_to_its_link() {
        let (key, blob) = link_seal("link-1", b"hunter2", None, &LIGHT).unwrap();
        assert_eq!(link_open("link-2", key.as_bytes(), &blob, None).err(), Some(Error::Decrypt));
    }

    #[test]
    fn a_passphrase_is_needed_when_set() {
        let (key, blob) = link_seal("link-1", b"hunter2", Some(b"open sesame"), &LIGHT).unwrap();
        assert!(link_needs_passphrase(&blob).unwrap());
        assert_eq!(link_open("link-1", key.as_bytes(), &blob, Some(b"open sesame")).unwrap(), b"hunter2");
        assert_eq!(link_open("link-1", key.as_bytes(), &blob, Some(b"wrong")).err(), Some(Error::Decrypt));
        assert_eq!(link_open("link-1", key.as_bytes(), &blob, None).err(), Some(Error::Decrypt));
    }

    #[test]
    fn the_passphrase_flag_cant_be_stripped() {
        let (key, mut blob) = link_seal("link-1", b"hunter2", Some(b"open sesame"), &LIGHT).unwrap();
        // A server removing the flag and the KDF header leaves bytes the content key no longer opens.
        blob[1] = 0;
        blob.drain(2..HEADER_PASS);
        assert_eq!(link_open("link-1", key.as_bytes(), &blob, None).err(), Some(Error::Decrypt));
    }

    #[test]
    fn refuses_weakened_or_abusive_kdf_headers() {
        let (key, mut blob) = link_seal("link-1", b"x", Some(b"pw"), &LIGHT).unwrap();
        blob[2 + SALT_LEN..2 + SALT_LEN + 4].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(link_open("link-1", key.as_bytes(), &blob, Some(b"pw")).err(), Some(Error::KdfParams));
        assert!(link_needs_passphrase(&[9, 0, 1]).is_err());
    }
}
