//! Handing the master key to a new device, assisted-recovery escrow, and fingerprints people can compare.

use crypto_box::{PublicKey as BoxPublic, SecretKey as BoxSecret};
use rand_core::OsRng;
use zeroize::Zeroize;

use crate::account::{KeyBundle, Keyring};
use crate::error::{Error, Result};
use crate::keys::Key32;
use crate::primitives::sha256;

const DEVICE_CONTEXT: &[u8] = b"pc/v1/device-handover";
const ESCROW_CONTEXT: &[u8] = b"pc/v1/escrow";

/// A new device asking to be let in. It shows its public key (as a QR code) and [`short_code`] of it; an unlocked
/// device checks the code and seals the master key to that public key. The server only relays sealed bytes.
pub struct DeviceRequest {
    secret: BoxSecret,
}

impl DeviceRequest {
    /// A fresh temporary key pair for this request.
    pub fn new() -> Self {
        DeviceRequest { secret: BoxSecret::generate(&mut OsRng) }
    }

    /// The public key to show/send to the approving device.
    pub fn public_key(&self) -> [u8; 32] {
        *self.secret.public_key().as_bytes()
    }

    /// Opens the hand-over from the approving device and unlocks this account on this device.
    pub fn receive(&self, sealed: &[u8], bundle: &KeyBundle) -> Result<Keyring> {
        let mut message = self.secret.unseal(sealed).map_err(|_| Error::Decrypt)?;
        let result = match message.strip_prefix(DEVICE_CONTEXT) {
            Some(master) => Keyring::from_master(master, bundle),
            None => Err(Error::Format("device hand-over context")),
        };
        message.zeroize();
        result
    }
}

impl Default for DeviceRequest {
    fn default() -> Self {
        Self::new()
    }
}

fn seal_to(public: &[u8], context: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    let public: [u8; 32] = public.try_into().map_err(|_| Error::InvalidKey)?;
    let mut message = context.to_vec();
    message.extend_from_slice(secret);
    let sealed = BoxPublic::from(public).seal(&mut OsRng, &message).map_err(|_| Error::InvalidKey);
    message.zeroize();
    sealed
}

impl Keyring {
    /// Seals this account's master key to a new device's temporary public key (device approval).
    pub fn seal_master_for_device(&self, device_public: &[u8]) -> Result<Vec<u8>> {
        seal_to(device_public, DEVICE_CONTEXT, self.master.as_bytes())
    }

    /// Seals the master key to the server's escrow public key (assisted recovery, opt-in). Only the escrow secret,
    /// which lives on the server outside the database, can open it.
    pub fn seal_master_for_escrow(&self, escrow_public: &[u8]) -> Result<Vec<u8>> {
        seal_to(escrow_public, ESCROW_CONTEXT, self.master.as_bytes())
    }
}

/// A new escrow key pair `(secret, public)` for the server's assisted-recovery setting.
pub fn escrow_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = BoxSecret::generate(&mut OsRng);
    (secret.to_bytes(), *secret.public_key().as_bytes())
}

/// Opens an escrowed master key (server side, after the recovery delay). Returns the master key bytes.
pub fn escrow_open(escrow_secret: &[u8], sealed: &[u8]) -> Result<Key32> {
    let mut secret_bytes: [u8; 32] = escrow_secret.try_into().map_err(|_| Error::InvalidKey)?;
    let secret = BoxSecret::from(secret_bytes);
    secret_bytes.zeroize();
    let mut message = secret.unseal(sealed).map_err(|_| Error::Decrypt)?;
    let result = match message.strip_prefix(ESCROW_CONTEXT) {
        Some(master) => Key32::from_slice(master),
        None => Err(Error::Format("escrow context")),
    };
    message.zeroize();
    result
}

/// Six digits both devices show during device approval, so the person can check they talk to each other.
pub fn short_code(public_key: &[u8]) -> String {
    let digest = sha256(public_key);
    let number = u32::from_be_bytes([0, digest[0], digest[1], digest[2]]) % 1_000_000;
    format!("{number:06}")
}

/// A fingerprint of an account's public keys (for comparing out of band before sharing): 6 groups of 5 digits.
pub fn fingerprint(box_public: &[u8], sign_public: &[u8]) -> String {
    let mut input = b"pc/v1/fingerprint".to_vec();
    input.extend_from_slice(box_public);
    input.extend_from_slice(sign_public);
    let digest = sha256(&input);
    digest
        .chunks(4)
        .take(6)
        .map(|c| format!("{:05}", u32::from_be_bytes([c[0], c[1], c[2], c[3]]) % 100_000))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::create_account;
    use crate::keys::KdfParams;

    fn fast_kdf() -> KdfParams {
        KdfParams { memory_kib: KdfParams::MIN_MEMORY_KIB, iterations: 2, parallelism: 1 }
    }

    #[test]
    fn device_hand_over_unlocks_the_new_device() {
        let account = create_account(b"passphrase for devices", fast_kdf()).unwrap();
        let request = DeviceRequest::new();
        let sealed = account.keyring.seal_master_for_device(&request.public_key()).unwrap();
        let keyring = request.receive(&sealed, &account.bundle).unwrap();
        assert_eq!(keyring.export_master_for_device(), account.keyring.export_master_for_device());

        // Another device's request can't open it.
        assert!(DeviceRequest::new().receive(&sealed, &account.bundle).is_err());
    }

    #[test]
    fn escrow_round_trip_and_contexts_do_not_mix() {
        let account = create_account(b"passphrase for escrow", fast_kdf()).unwrap();
        let (secret, public) = escrow_keypair();
        let sealed = account.keyring.seal_master_for_escrow(&public).unwrap();
        let master = escrow_open(&secret, &sealed).unwrap();
        assert_eq!(master.as_bytes(), &account.keyring.export_master_for_device());

        // A device hand-over sealed to the same key is not accepted as an escrow (different context).
        let device_sealed = account.keyring.seal_master_for_device(&public).unwrap();
        assert!(escrow_open(&secret, &device_sealed).is_err());
    }

    #[test]
    fn codes_are_stable_and_shaped() {
        assert_eq!(short_code(b"abc"), short_code(b"abc"));
        assert_eq!(short_code(b"abc").len(), 6);
        let fp = fingerprint(&[1u8; 32], &[2u8; 32]);
        assert_eq!(fp.split(' ').count(), 6);
        assert!(fp.split(' ').all(|g| g.len() == 5));
    }
}
