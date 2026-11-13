//! The `.pcipher` file format (spec: `spec/pcipher.md`). Streaming: files of any size are encrypted and decrypted
//! chunk by chunk, so memory use stays at about one chunk.
//!
//! ```text
//! offset size
//!  0      7   magic "PCIPHER"
//!  7      1   format version (1)
//!  8      1   mode: 1 = passphrase, 2 = vault key
//!  9      1   kdf id: 1 = Argon2id (mode 1), 0 (mode 2)
//! 10     12   Argon2id memory KiB, iterations, parallelism (u32 LE each; zero in mode 2)
//! 22     16   salt (Argon2id salt in mode 1, HKDF salt in mode 2)
//! 38      8   key id (mode 2: first 8 bytes of SHA-256 of the vault id; zero in mode 1)
//! 46      4   chunk size (u32 LE)
//! 50      4   metadata length (u32 LE)
//! 54     19   STREAM nonce prefix
//! 73          segments: metadata (encrypted), then content chunks; the last chunk is marked final
//! ```
//! Every segment uses the whole header as associated data. Segment = plaintext + 16-byte tag. The STREAM
//! construction (XChaCha20-Poly1305, 32-bit counter, last-block flag) detects reordered, dropped or truncated chunks.

use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroize;

use crate::account::Keyring;
use crate::error::{Error, Result};
use crate::keys::{KdfParams, Key32};
use crate::primitives::{argon2id, hkdf, random_bytes, sha256, SALT_LEN, TAG_LEN};

const MAGIC: &[u8; 7] = b"PCIPHER";
const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const NONCE_PREFIX_LEN: usize = 19;
const INFO_PASSPHRASE: &[u8] = b"pc/v1/pcipher";
/// Header length in bytes.
pub const HEADER_LEN: usize = 73;
/// Default content chunk size: 1 MiB.
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
const MIN_CHUNK: u32 = 4 * 1024;
const MAX_CHUNK: u32 = 16 * 1024 * 1024;
const MAX_METADATA: u32 = 64 * 1024;

/// How a file's key is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcipherMode {
    /// From a passphrase with Argon2id.
    Passphrase,
    /// From one of the person's vault keys.
    VaultKey,
}

/// A parsed header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcipherHeader {
    /// Key mode.
    pub mode: PcipherMode,
    /// Argon2id parameters (passphrase mode).
    pub kdf: KdfParams,
    /// Salt.
    pub salt: [u8; SALT_LEN],
    /// Which vault (vault mode): first 8 bytes of SHA-256 of the vault id.
    pub key_id: [u8; 8],
    /// Content chunk size.
    pub chunk_size: u32,
    /// Plaintext metadata length.
    pub metadata_len: u32,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    raw: Vec<u8>,
}

impl PcipherHeader {
    /// The raw header bytes (written at the start of the file).
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Whether this file was made with the given vault (vault mode).
    pub fn matches_vault(&self, vault_id: &str) -> bool {
        self.mode == PcipherMode::VaultKey && self.key_id == vault_key_id(vault_id)
    }
}

fn vault_key_id(vault_id: &str) -> [u8; 8] {
    let digest = sha256(vault_id.as_bytes());
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest[..8]);
    id
}

fn build_header(
    mode: PcipherMode,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    key_id: [u8; 8],
    chunk_size: u32,
    metadata_len: u32,
) -> PcipherHeader {
    let nonce_prefix = random_bytes::<NONCE_PREFIX_LEN>();
    let mut raw = Vec::with_capacity(HEADER_LEN);
    raw.extend_from_slice(MAGIC);
    raw.push(VERSION);
    match mode {
        PcipherMode::Passphrase => {
            raw.push(1);
            raw.push(KDF_ARGON2ID);
            raw.extend_from_slice(&kdf.memory_kib.to_le_bytes());
            raw.extend_from_slice(&kdf.iterations.to_le_bytes());
            raw.extend_from_slice(&kdf.parallelism.to_le_bytes());
        }
        PcipherMode::VaultKey => {
            raw.push(2);
            raw.push(0);
            raw.extend_from_slice(&[0u8; 12]);
        }
    }
    raw.extend_from_slice(&salt);
    raw.extend_from_slice(&key_id);
    raw.extend_from_slice(&chunk_size.to_le_bytes());
    raw.extend_from_slice(&metadata_len.to_le_bytes());
    raw.extend_from_slice(&nonce_prefix);
    debug_assert_eq!(raw.len(), HEADER_LEN);
    PcipherHeader { mode, kdf, salt, key_id, chunk_size, metadata_len, nonce_prefix, raw }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

/// Reads the first [`HEADER_LEN`] bytes of a file.
pub fn parse_header(bytes: &[u8]) -> Result<PcipherHeader> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::Format("file too short to be a .pcipher file"));
    }
    let raw = &bytes[..HEADER_LEN];
    if &raw[..7] != MAGIC {
        return Err(Error::Format("not a .pcipher file"));
    }
    if raw[7] != VERSION {
        return Err(Error::Format("unsupported .pcipher version"));
    }
    let mode = match (raw[8], raw[9]) {
        (1, KDF_ARGON2ID) => PcipherMode::Passphrase,
        (2, 0) => PcipherMode::VaultKey,
        _ => return Err(Error::Format("unknown .pcipher mode")),
    };
    let kdf = KdfParams { memory_kib: u32_at(raw, 10), iterations: u32_at(raw, 14), parallelism: u32_at(raw, 18) };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&raw[22..38]);
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&raw[38..46]);
    let chunk_size = u32_at(raw, 46);
    let metadata_len = u32_at(raw, 50);
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) || metadata_len > MAX_METADATA {
        return Err(Error::Format("chunk size or metadata length out of range"));
    }
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&raw[54..73]);
    Ok(PcipherHeader { mode, kdf, salt, key_id, chunk_size, metadata_len, nonce_prefix, raw: raw.to_vec() })
}

fn passphrase_file_key(passphrase: &[u8], header: &PcipherHeader) -> Result<Key32> {
    let base = argon2id(passphrase, &header.salt, &header.kdf)?;
    Ok(hkdf(base.as_bytes(), &header.salt, INFO_PASSPHRASE))
}

fn cipher(key: &Key32) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()))
}

/// Streams a file into the `.pcipher` format.
pub struct PcipherEncryptor {
    stream: Option<EncryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
    chunk_size: usize,
    buffer: Vec<u8>,
}

impl PcipherEncryptor {
    /// Starts a passphrase-protected file. Returns the encryptor and the first bytes to write (header + metadata).
    pub fn with_passphrase(
        passphrase: &[u8],
        kdf: KdfParams,
        metadata: &[u8],
        chunk_size: u32,
    ) -> Result<(Self, Vec<u8>)> {
        check_sizes(chunk_size, metadata)?;
        let header = build_header(
            PcipherMode::Passphrase,
            kdf,
            random_bytes::<SALT_LEN>(),
            [0u8; 8],
            chunk_size,
            metadata.len() as u32,
        );
        let key = passphrase_file_key(passphrase, &header)?;
        Self::start(header, &key, metadata)
    }

    /// Starts a file protected by one of the person's vault keys (no passphrase to remember).
    pub fn with_vault(keyring: &Keyring, vault_id: &str, metadata: &[u8], chunk_size: u32) -> Result<(Self, Vec<u8>)> {
        check_sizes(chunk_size, metadata)?;
        let header = build_header(
            PcipherMode::VaultKey,
            KdfParams { memory_kib: 0, iterations: 0, parallelism: 0 },
            random_bytes::<SALT_LEN>(),
            vault_key_id(vault_id),
            chunk_size,
            metadata.len() as u32,
        );
        let key = keyring.file_key(vault_id, &header.salt)?;
        Self::start(header, &key, metadata)
    }

    fn start(header: PcipherHeader, key: &Key32, metadata: &[u8]) -> Result<(Self, Vec<u8>)> {
        let mut stream =
            EncryptorBE32::from_aead(cipher(key), header.nonce_prefix.as_slice().into());
        let aad = header.raw.clone();
        let sealed_meta = stream
            .encrypt_next(Payload { msg: metadata, aad: &aad })
            .map_err(|_| Error::Format("metadata encryption"))?;
        let mut first = header.raw.clone();
        first.extend_from_slice(&sealed_meta);
        let chunk_size = header.chunk_size as usize;
        Ok((PcipherEncryptor { stream: Some(stream), aad, chunk_size, buffer: Vec::new() }, first))
    }

    /// Adds plaintext. Returns the encrypted bytes ready to write (may be empty while a chunk fills up).
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let stream = self.stream.as_mut().ok_or(Error::Finished)?;
        self.buffer.extend_from_slice(data);
        let mut out = Vec::new();
        // Keep at least one byte back so the final chunk is always written by `finish` with the last flag.
        while self.buffer.len() > self.chunk_size {
            let rest = self.buffer.split_off(self.chunk_size);
            let segment = stream
                .encrypt_next(Payload { msg: &self.buffer, aad: &self.aad })
                .map_err(|_| Error::Format("chunk encryption"))?;
            self.buffer.zeroize();
            self.buffer = rest;
            out.extend_from_slice(&segment);
        }
        Ok(out)
    }

    /// Writes the final chunk. The encryptor can't be used after this.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let stream = self.stream.take().ok_or(Error::Finished)?;
        let segment = stream
            .encrypt_last(Payload { msg: &self.buffer, aad: &self.aad })
            .map_err(|_| Error::Format("final chunk encryption"))?;
        self.buffer.zeroize();
        self.buffer.clear();
        Ok(segment)
    }
}

fn check_sizes(chunk_size: u32, metadata: &[u8]) -> Result<()> {
    if !(MIN_CHUNK..=MAX_CHUNK).contains(&chunk_size) || metadata.len() as u64 > MAX_METADATA as u64 {
        return Err(Error::Format("chunk size or metadata length out of range"));
    }
    Ok(())
}

/// Streams a `.pcipher` file back to plaintext. Feed it the bytes after the header.
pub struct PcipherDecryptor {
    stream: Option<DecryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
    segment_len: usize,
    metadata_segment_len: usize,
    metadata: Option<Vec<u8>>,
    buffer: Vec<u8>,
}

impl PcipherDecryptor {
    /// Opens a passphrase file.
    pub fn with_passphrase(header: &PcipherHeader, passphrase: &[u8]) -> Result<Self> {
        if header.mode != PcipherMode::Passphrase {
            return Err(Error::Format("this file is locked with a vault key, not a passphrase"));
        }
        let key = passphrase_file_key(passphrase, header)?;
        Ok(Self::start(header, &key))
    }

    /// Opens a vault-key file with an unlocked keyring.
    pub fn with_vault(header: &PcipherHeader, keyring: &Keyring, vault_id: &str) -> Result<Self> {
        if !header.matches_vault(vault_id) {
            return Err(Error::Format("this file was not made with this vault"));
        }
        let key = keyring.file_key(vault_id, &header.salt)?;
        Ok(Self::start(header, &key))
    }

    fn start(header: &PcipherHeader, key: &Key32) -> Self {
        PcipherDecryptor {
            stream: Some(DecryptorBE32::from_aead(cipher(key), header.nonce_prefix.as_slice().into())),
            aad: header.raw.clone(),
            segment_len: header.chunk_size as usize + TAG_LEN,
            metadata_segment_len: header.metadata_len as usize + TAG_LEN,
            metadata: None,
            buffer: Vec::new(),
        }
    }

    /// The file's metadata, once its segment has been read (wrong passphrase shows up here as [`Error::Decrypt`]).
    pub fn metadata(&self) -> Option<&[u8]> {
        self.metadata.as_deref()
    }

    /// Adds encrypted bytes. Returns the plaintext that is ready.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let stream = self.stream.as_mut().ok_or(Error::Finished)?;
        self.buffer.extend_from_slice(data);
        if self.metadata.is_none() {
            if self.buffer.len() < self.metadata_segment_len {
                return Ok(Vec::new());
            }
            let rest = self.buffer.split_off(self.metadata_segment_len);
            let meta = stream
                .decrypt_next(Payload { msg: &self.buffer, aad: &self.aad })
                .map_err(|_| Error::Decrypt)?;
            self.metadata = Some(meta);
            self.buffer = rest;
        }
        let mut out = Vec::new();
        // Hold the last full segment back: only `finish` knows whether it is the final one.
        while self.buffer.len() > self.segment_len {
            let rest = self.buffer.split_off(self.segment_len);
            let plain = stream
                .decrypt_next(Payload { msg: &self.buffer, aad: &self.aad })
                .map_err(|_| Error::Decrypt)?;
            self.buffer = rest;
            out.extend_from_slice(&plain);
        }
        Ok(out)
    }

    /// Decrypts the final chunk and checks nothing was cut off.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let stream = self.stream.take().ok_or(Error::Finished)?;
        if self.metadata.is_none() || self.buffer.len() < TAG_LEN {
            return Err(Error::Format("file is truncated"));
        }
        let plain = stream
            .decrypt_last(Payload { msg: &self.buffer, aad: &self.aad })
            .map_err(|_| Error::Decrypt)?;
        self.buffer.clear();
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::create_account;

    fn fast_kdf() -> KdfParams {
        KdfParams { memory_kib: KdfParams::MIN_MEMORY_KIB, iterations: 2, parallelism: 1 }
    }

    fn encrypt(data: &[u8], piece: usize, chunk: u32) -> Vec<u8> {
        let (mut enc, mut file) =
            PcipherEncryptor::with_passphrase(b"file passphrase", fast_kdf(), b"{\"name\":\"a.txt\"}", chunk).unwrap();
        for part in data.chunks(piece.max(1)) {
            file.extend(enc.push(part).unwrap());
        }
        file.extend(enc.finish().unwrap());
        file
    }

    fn decrypt(file: &[u8], passphrase: &[u8], piece: usize) -> Result<(Vec<u8>, Vec<u8>)> {
        let header = parse_header(file)?;
        let mut dec = PcipherDecryptor::with_passphrase(&header, passphrase)?;
        let mut out = Vec::new();
        for part in file[HEADER_LEN..].chunks(piece.max(1)) {
            out.extend(dec.push(part)?);
        }
        out.extend(dec.finish()?);
        Ok((dec.metadata().unwrap().to_vec(), out))
    }

    #[test]
    fn round_trips_any_size_and_any_piece_size() {
        let chunk = MIN_CHUNK;
        for size in [0usize, 1, 4095, 4096, 4097, 8192, 20_000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            for piece in [1usize, 1000, 4096, 50_000] {
                if size > 5000 && piece == 1 {
                    continue;
                }
                let file = encrypt(&data, piece, chunk);
                let (meta, plain) = decrypt(&file, b"file passphrase", 777).unwrap();
                assert_eq!(meta, b"{\"name\":\"a.txt\"}");
                assert_eq!(plain, data, "size {size} piece {piece}");
            }
        }
    }

    #[test]
    fn wrong_passphrase_truncation_and_tampering_fail() {
        let data = vec![9u8; 10_000];
        let file = encrypt(&data, 3000, MIN_CHUNK);
        assert_eq!(decrypt(&file, b"not the passphrase", 4096).err(), Some(Error::Decrypt));
        // Cut off the last chunk: the previous chunk is not marked final, so it fails.
        let cut = &file[..file.len() - 100];
        assert!(decrypt(cut, b"file passphrase", 4096).is_err());
        let cut_at_boundary = &file[..HEADER_LEN + 16 + 16 + (MIN_CHUNK as usize + 16) * 2];
        assert!(decrypt(cut_at_boundary, b"file passphrase", 4096).is_err());
        // Flip a byte in the header: every segment's associated data changes.
        let mut tampered = file.clone();
        tampered[50] ^= 1;
        assert!(decrypt(&tampered, b"file passphrase", 4096).is_err());
        // Not a pcipher file at all.
        assert!(parse_header(b"hello world, this is not a pcipher file at all, it is long enough for a header....").is_err());
    }

    #[test]
    fn vault_key_mode() {
        let mut account = create_account(b"account passphrase x", fast_kdf()).unwrap();
        account.keyring.create_vault("vault-a");
        account.keyring.create_vault("vault-b");
        let (mut enc, mut file) =
            PcipherEncryptor::with_vault(&account.keyring, "vault-a", b"{}", DEFAULT_CHUNK_SIZE).unwrap();
        file.extend(enc.push(b"secret contents").unwrap());
        file.extend(enc.finish().unwrap());

        let header = parse_header(&file).unwrap();
        assert!(header.matches_vault("vault-a"));
        assert!(PcipherDecryptor::with_vault(&header, &account.keyring, "vault-b").is_err());
        assert!(PcipherDecryptor::with_passphrase(&header, b"anything").is_err());
        let mut dec = PcipherDecryptor::with_vault(&header, &account.keyring, "vault-a").unwrap();
        let mut out = dec.push(&file[HEADER_LEN..]).unwrap();
        out.extend(dec.finish().unwrap());
        assert_eq!(out, b"secret contents");
    }

    #[test]
    fn a_malicious_header_cannot_ask_for_huge_or_weak_kdf() {
        let file = encrypt(b"x", 1, MIN_CHUNK);
        let mut weak = file.clone();
        weak[10..14].copy_from_slice(&1024u32.to_le_bytes());
        let header = parse_header(&weak).unwrap();
        assert_eq!(PcipherDecryptor::with_passphrase(&header, b"file passphrase").err(), Some(Error::KdfParams));
    }
}
