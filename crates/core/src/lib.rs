//! Potent Cipher cryptography core.
//!
//! This crate is the ONE implementation of every cryptographic operation in Potent Cipher. It runs only on the
//! user's device (compiled to WebAssembly for the web app and the extension, natively for the desktop app).
//! Design: `docs/01-encryption-design.md`. File format: `spec/pcipher.md`.
//!
//! Key hierarchy (all keys 32 random bytes unless noted):
//! ```text
//! passphrase --Argon2id--> KEK  wraps  Master Key (MK)
//! Recovery Key (16 B) --HKDF--> recovery KEK  wraps  MK (second copy)
//! MK wraps the identity secrets (X25519 + Ed25519) and every master-mode Vault Key (VK)
//! vault passphrase --Argon2id--> vault KEK  wraps  the VK of a custom-key vault
//! VK wraps a random Item Key (IK) per item; IK encrypts the item
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod account;
mod device;
mod encoding;
mod error;
mod keys;
mod link;
mod password;
mod pcipher;
mod primitives;
mod totp;
mod vault;

pub use account::{create_account, KeyBundle, Keyring, NewAccount, RecoveryRotation};
pub use device::{escrow_keypair, escrow_open, fingerprint, short_code, DeviceRequest};
pub use encoding::{decode_recovery_key, encode_recovery_key};
pub use error::{Error, Result};
pub use keys::{KdfParams, Key32};
pub use link::{link_needs_passphrase, link_open, link_seal};
pub use password::{generate_passphrase, generate_password, passphrase_meets_minimum};
pub use pcipher::{
    parse_header, PcipherDecryptor, PcipherEncryptor, PcipherHeader, PcipherMode, DEFAULT_CHUNK_SIZE,
    HEADER_LEN,
};
pub use totp::{totp_code, totp_secret_from_base32, TotpAlgorithm};
pub use vault::SealedItem;

/// Version of the key bundle and item formats written by this crate.
pub const FORMAT_VERSION: u8 = 1;
