//! Account setup and unlocking: the key bundle the server stores, and the keyring that lives only on the device.

use std::collections::BTreeMap;

use crypto_box::SecretKey as BoxSecret;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use zeroize::Zeroize;

use crate::encoding::{decode_recovery_key, encode_recovery_key, RECOVERY_KEY_LEN};
use crate::error::{Error, Result};
use crate::keys::{KdfParams, Key32};
use crate::primitives::{argon2id, hkdf, open, random_bytes, seal, unwrap_key, wrap_key, SALT_LEN};
use crate::FORMAT_VERSION;

const AAD_MK_PASSPHRASE: &[u8] = b"pc/v1/mk/passphrase";
const AAD_MK_RECOVERY: &[u8] = b"pc/v1/mk/recovery";
const AAD_IDENTITY: &[u8] = b"pc/v1/identity";
const RECOVERY_SALT: &[u8] = b"pc/v1/recovery-salt";
const RECOVERY_INFO: &[u8] = b"pc/v1/recovery";

/// What the server stores for an account. Everything here is public or wrapped; none of it opens anything alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    /// Format version.
    pub version: u8,
    /// Argon2id parameters for the passphrase.
    pub kdf: KdfParams,
    /// Argon2id salt (random per account, changes with the passphrase).
    pub salt: [u8; SALT_LEN],
    /// The master key wrapped by the passphrase key.
    pub wrapped_mk: Vec<u8>,
    /// The master key wrapped by the recovery key.
    pub wrapped_mk_recovery: Vec<u8>,
    /// X25519 public key (others seal vault keys and device hand-overs to it).
    pub box_public: [u8; 32],
    /// Ed25519 public key (verifies this account's signatures).
    pub sign_public: [u8; 32],
    /// The X25519 and Ed25519 secret keys (64 bytes), wrapped by the master key.
    pub wrapped_identity: Vec<u8>,
}

impl KeyBundle {
    /// Serialises the bundle for storage:
    /// `version | kdf (3 x u32 LE) | salt 16 | box_public 32 | sign_public 32 | 3 x (u32 LE length + bytes)` for
    /// `wrapped_mk`, `wrapped_mk_recovery`, `wrapped_identity`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.version];
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.iterations.to_le_bytes());
        out.extend_from_slice(&self.kdf.parallelism.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.box_public);
        out.extend_from_slice(&self.sign_public);
        for part in [&self.wrapped_mk, &self.wrapped_mk_recovery, &self.wrapped_identity] {
            out.extend_from_slice(&(part.len() as u32).to_le_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// Reads a bundle made by [`KeyBundle::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const FIXED: usize = 1 + 12 + SALT_LEN + 32 + 32;
        if bytes.len() < FIXED || bytes[0] != FORMAT_VERSION {
            return Err(Error::Format("key bundle"));
        }
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
        let kdf = KdfParams { memory_kib: u32_at(1), iterations: u32_at(5), parallelism: u32_at(9) };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[13..29]);
        let mut box_public = [0u8; 32];
        box_public.copy_from_slice(&bytes[29..61]);
        let mut sign_public = [0u8; 32];
        sign_public.copy_from_slice(&bytes[61..93]);
        let mut at = FIXED;
        let mut parts = Vec::with_capacity(3);
        for _ in 0..3 {
            if bytes.len() < at + 4 {
                return Err(Error::Format("key bundle"));
            }
            let len = u32_at(at) as usize;
            at += 4;
            if bytes.len() < at + len {
                return Err(Error::Format("key bundle"));
            }
            parts.push(bytes[at..at + len].to_vec());
            at += len;
        }
        if at != bytes.len() {
            return Err(Error::Format("key bundle"));
        }
        let wrapped_identity = parts.pop().expect("3 parts");
        let wrapped_mk_recovery = parts.pop().expect("3 parts");
        let wrapped_mk = parts.pop().expect("3 parts");
        Ok(KeyBundle {
            version: bytes[0],
            kdf,
            salt,
            wrapped_mk,
            wrapped_mk_recovery,
            box_public,
            sign_public,
            wrapped_identity,
        })
    }
}

/// Result of [`create_account`].
pub struct NewAccount {
    /// Store this on the server.
    pub bundle: KeyBundle,
    /// Show this once to the person; it is never stored anywhere by us.
    pub recovery_key: String,
    /// The unlocked keyring for this device.
    pub keyring: Keyring,
}

/// Result of [`Keyring::rotate_recovery_key`].
pub struct RecoveryRotation {
    /// The new recovery key to show once.
    pub recovery_key: String,
    /// Replaces `wrapped_mk_recovery` in the bundle.
    pub wrapped_mk_recovery: Vec<u8>,
}

/// Creates the keys of a new account from the vault passphrase.
pub fn create_account(passphrase: &[u8], kdf: KdfParams) -> Result<NewAccount> {
    let master = Key32::random();
    let salt = random_bytes::<SALT_LEN>();
    let kek = argon2id(passphrase, &salt, &kdf)?;
    let wrapped_mk = wrap_key(&kek, &master, AAD_MK_PASSPHRASE);

    let mut recovery_secret = random_bytes::<RECOVERY_KEY_LEN>();
    let recovery_key = encode_recovery_key(&recovery_secret);
    let wrapped_mk_recovery = wrap_key(&recovery_kek(&recovery_secret), &master, AAD_MK_RECOVERY);
    recovery_secret.zeroize();

    let box_secret = BoxSecret::generate(&mut OsRng);
    let signing = SigningKey::generate(&mut OsRng);
    let mut identity = [0u8; 64];
    identity[..32].copy_from_slice(&box_secret.to_bytes());
    identity[32..].copy_from_slice(&signing.to_bytes());
    let wrapped_identity = seal(&master, &identity, AAD_IDENTITY);
    identity.zeroize();

    let bundle = KeyBundle {
        version: FORMAT_VERSION,
        kdf,
        salt,
        wrapped_mk,
        wrapped_mk_recovery,
        box_public: *box_secret.public_key().as_bytes(),
        sign_public: signing.verifying_key().to_bytes(),
        wrapped_identity,
    };
    let keyring = Keyring { master, vaults: BTreeMap::new(), box_secret: Some(box_secret), signing: Some(signing) };
    Ok(NewAccount { bundle, recovery_key, keyring })
}

fn recovery_kek(secret: &[u8; RECOVERY_KEY_LEN]) -> Key32 {
    hkdf(secret, RECOVERY_SALT, RECOVERY_INFO)
}

/// The unlocked keys of one account, kept only in this device's memory. Dropping or [`Keyring::lock`]ing it wipes them.
pub struct Keyring {
    pub(crate) master: Key32,
    pub(crate) vaults: BTreeMap<String, Key32>,
    pub(crate) box_secret: Option<BoxSecret>,
    pub(crate) signing: Option<SigningKey>,
}

impl Keyring {
    /// Unlocks with the vault passphrase.
    pub fn unlock_with_passphrase(passphrase: &[u8], bundle: &KeyBundle) -> Result<Self> {
        let kek = argon2id(passphrase, &bundle.salt, &bundle.kdf)?;
        let master = unwrap_key(&kek, &bundle.wrapped_mk, AAD_MK_PASSPHRASE)?;
        Self::with_master(master, bundle)
    }

    /// Unlocks with the recovery key (forgotten passphrase).
    pub fn unlock_with_recovery_key(recovery_key: &str, bundle: &KeyBundle) -> Result<Self> {
        let mut secret = decode_recovery_key(recovery_key)?;
        let kek = recovery_kek(&secret);
        secret.zeroize();
        let master = unwrap_key(&kek, &bundle.wrapped_mk_recovery, AAD_MK_RECOVERY)?;
        Self::with_master(master, bundle)
    }

    /// Unlocks from a master key that was kept on this device ("remember on this device"), handed over by another
    /// device, or released by assisted recovery. Checks it really is this account's key.
    pub fn from_master(master: &[u8], bundle: &KeyBundle) -> Result<Self> {
        Self::with_master(Key32::from_slice(master)?, bundle)
    }

    fn with_master(master: Key32, bundle: &KeyBundle) -> Result<Self> {
        let mut identity = open(&master, &bundle.wrapped_identity, AAD_IDENTITY)?;
        if identity.len() != 64 {
            identity.zeroize();
            return Err(Error::Format("identity length"));
        }
        let mut box_bytes = [0u8; 32];
        let mut sign_bytes = [0u8; 32];
        box_bytes.copy_from_slice(&identity[..32]);
        sign_bytes.copy_from_slice(&identity[32..]);
        identity.zeroize();
        let box_secret = BoxSecret::from(box_bytes);
        let signing = SigningKey::from_bytes(&sign_bytes);
        box_bytes.zeroize();
        sign_bytes.zeroize();
        if box_secret.public_key().as_bytes() != &bundle.box_public
            || signing.verifying_key().to_bytes() != bundle.sign_public
        {
            return Err(Error::Decrypt);
        }
        Ok(Keyring { master, vaults: BTreeMap::new(), box_secret: Some(box_secret), signing: Some(signing) })
    }

    /// New passphrase: returns the new salt and wrapped master key. Nothing else changes.
    pub fn rewrap_for_passphrase(&self, new_passphrase: &[u8], kdf: KdfParams) -> Result<([u8; SALT_LEN], Vec<u8>)> {
        let salt = random_bytes::<SALT_LEN>();
        let kek = argon2id(new_passphrase, &salt, &kdf)?;
        Ok((salt, wrap_key(&kek, &self.master, AAD_MK_PASSPHRASE)))
    }

    /// Makes a new recovery key (the old one stops working once the server stores the new wrapped copy).
    pub fn rotate_recovery_key(&self) -> RecoveryRotation {
        let mut secret = random_bytes::<RECOVERY_KEY_LEN>();
        let recovery_key = encode_recovery_key(&secret);
        let wrapped_mk_recovery = wrap_key(&recovery_kek(&secret), &self.master, AAD_MK_RECOVERY);
        secret.zeroize();
        RecoveryRotation { recovery_key, wrapped_mk_recovery }
    }

    /// The raw master key, only to keep it on this device under a non-extractable device key
    /// ("remember on this device"). The caller must wipe the returned bytes.
    pub fn export_master_for_device(&self) -> [u8; 32] {
        *self.master.as_bytes()
    }

    /// Signs a message with this account's Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer;
        let signing = self.signing.as_ref().ok_or(Error::Finished)?;
        Ok(signing.sign(message).to_bytes())
    }

    /// Wipes every key held by this keyring.
    pub fn lock(&mut self) {
        self.master.zeroize();
        self.vaults.clear();
        self.box_secret = None;
        self.signing = None;
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        self.lock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_kdf() -> KdfParams {
        KdfParams { memory_kib: KdfParams::MIN_MEMORY_KIB, iterations: 2, parallelism: 1 }
    }

    #[test]
    fn create_unlock_and_recover() {
        let new = create_account(b"correct horse battery staple", fast_kdf()).unwrap();
        let bundle = new.bundle.clone();

        let unlocked = Keyring::unlock_with_passphrase(b"correct horse battery staple", &bundle).unwrap();
        assert_eq!(unlocked.master, new.keyring.master);

        assert_eq!(
            Keyring::unlock_with_passphrase(b"wrong passphrase!!", &bundle).err(),
            Some(Error::Decrypt)
        );

        let recovered = Keyring::unlock_with_recovery_key(&new.recovery_key, &bundle).unwrap();
        assert_eq!(recovered.master, new.keyring.master);
    }

    #[test]
    fn change_passphrase_keeps_the_master_key() {
        let new = create_account(b"first passphrase here", fast_kdf()).unwrap();
        let mut bundle = new.bundle.clone();
        let (salt, wrapped) = new.keyring.rewrap_for_passphrase(b"second passphrase here", fast_kdf()).unwrap();
        bundle.salt = salt;
        bundle.wrapped_mk = wrapped;
        let unlocked = Keyring::unlock_with_passphrase(b"second passphrase here", &bundle).unwrap();
        assert_eq!(unlocked.master, new.keyring.master);
        assert!(Keyring::unlock_with_passphrase(b"first passphrase here", &bundle).is_err());
    }

    #[test]
    fn rotated_recovery_key_replaces_the_old_one() {
        let new = create_account(b"some long passphrase", fast_kdf()).unwrap();
        let mut bundle = new.bundle.clone();
        let rotation = new.keyring.rotate_recovery_key();
        bundle.wrapped_mk_recovery = rotation.wrapped_mk_recovery;
        assert!(Keyring::unlock_with_recovery_key(&rotation.recovery_key, &bundle).is_ok());
        assert!(Keyring::unlock_with_recovery_key(&new.recovery_key, &bundle).is_err());
    }

    #[test]
    fn a_foreign_master_key_is_refused() {
        let a = create_account(b"account a passphrase", fast_kdf()).unwrap();
        let b = create_account(b"account b passphrase", fast_kdf()).unwrap();
        let foreign = b.keyring.export_master_for_device();
        assert!(Keyring::from_master(&foreign, &a.bundle).is_err());
        let own = a.keyring.export_master_for_device();
        assert!(Keyring::from_master(&own, &a.bundle).is_ok());
    }

    #[test]
    fn bundle_bytes_round_trip_and_reject_garbage() {
        let new = create_account(b"bundle passphrase!", fast_kdf()).unwrap();
        let bytes = new.bundle.to_bytes();
        assert_eq!(KeyBundle::from_bytes(&bytes).unwrap(), new.bundle);
        assert!(KeyBundle::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(KeyBundle::from_bytes(&longer).is_err());
        assert!(KeyBundle::from_bytes(b"nope").is_err());
    }

    #[test]
    fn weak_kdf_params_are_refused() {
        let weak = KdfParams { memory_kib: 1024, iterations: 1, parallelism: 1 };
        assert_eq!(create_account(b"whatever passphrase", weak).err(), Some(Error::KdfParams));
    }
}
