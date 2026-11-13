use core::fmt;

/// Everything that can go wrong. Messages are generic on purpose: they never say which secret was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Authenticated decryption failed: wrong key/passphrase, or the data was changed or damaged.
    Decrypt,
    /// The key derivation parameters are outside the allowed range (protects against weakened or abusive params).
    KdfParams,
    /// The key derivation itself failed.
    Kdf,
    /// A key or public key had the wrong length or form.
    InvalidKey,
    /// The recovery key is mistyped (bad characters, length or checksum).
    InvalidRecoveryKey,
    /// Encrypted data or a file header is malformed.
    Format(&'static str),
    /// A vault was used before it was opened in the keyring.
    VaultNotOpen,
    /// The encryptor/decryptor was used after it finished.
    Finished,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decrypt => f.write_str("decryption failed: wrong key or damaged data"),
            Error::KdfParams => f.write_str("key derivation parameters are out of range"),
            Error::Kdf => f.write_str("key derivation failed"),
            Error::InvalidKey => f.write_str("invalid key"),
            Error::InvalidRecoveryKey => f.write_str("invalid recovery key"),
            Error::Format(what) => write!(f, "malformed data: {what}"),
            Error::VaultNotOpen => f.write_str("vault is not open"),
            Error::Finished => f.write_str("stream already finished"),
        }
    }
}

impl std::error::Error for Error {}

/// Result with the crate's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
