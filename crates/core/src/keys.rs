use core::fmt;

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// A 32-byte secret key. Wiped from memory when dropped; never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    /// A fresh random key from the operating system's CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Key32(bytes)
    }

    /// Copies a key from bytes (must be exactly 32).
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Key32(array))
    }

    pub(crate) fn from_array(bytes: [u8; 32]) -> Self {
        Key32(bytes)
    }

    /// The raw key bytes. Only for passing into primitives; never store or log them.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Key32 {}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

/// Argon2id parameters. Stored next to the salt so they can be raised later without breaking old data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl KdfParams {
    /// Lowest memory a client accepts (OWASP minimum for Argon2id). A server can't push weaker params.
    pub const MIN_MEMORY_KIB: u32 = 19 * 1024;
    /// Highest memory a client accepts (so a malicious header can't exhaust the device).
    pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;

    /// The default for new accounts and files: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: KdfParams = KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 };

    /// Checks the parameters are inside the allowed range.
    pub fn validate(&self) -> Result<()> {
        let ok = (Self::MIN_MEMORY_KIB..=Self::MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (2..=10).contains(&self.iterations)
            && (1..=8).contains(&self.parallelism);
        if ok {
            Ok(())
        } else {
            Err(Error::KdfParams)
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}
