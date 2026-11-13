//! Vaults and items. Every item has its own random key, wrapped by its vault's key. Ciphertexts are bound to the
//! item id and vault id, so the server can't move or swap them.

use zeroize::Zeroize;

use crate::account::Keyring;
use crate::error::{Error, Result};
use crate::keys::{KdfParams, Key32};
use crate::primitives::{aad, argon2id, hkdf, open, random_bytes, seal, unwrap_key, wrap_key, SALT_LEN};

const AAD_VK: &[u8] = b"pc/v1/vk";
const AAD_VK_CUSTOM: &[u8] = b"pc/v1/vk-custom";
const AAD_IK: &[u8] = b"pc/v1/ik";
const AAD_ITEM: &[u8] = b"pc/v1/item";
const INFO_FILE: &[u8] = b"pc/v1/pcipher-vault";

/// An encrypted item as stored on the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedItem {
    /// The item key, wrapped by the vault key.
    pub wrapped_item_key: Vec<u8>,
    /// The item content (label, value, notes...), encrypted with the item key.
    pub ciphertext: Vec<u8>,
}

impl Keyring {
    /// Creates a vault protected by the master key. Returns the wrapped vault key to store.
    pub fn create_vault(&mut self, vault_id: &str) -> Vec<u8> {
        let vault_key = Key32::random();
        let wrapped = wrap_key(&self.master, &vault_key, &aad(&[AAD_VK, vault_id.as_bytes()]));
        self.vaults.insert(vault_id.to_owned(), vault_key);
        wrapped
    }

    /// Creates a vault locked by its own passphrase (Pro). Returns the salt and wrapped vault key to store.
    pub fn create_custom_vault(
        &mut self,
        vault_id: &str,
        vault_passphrase: &[u8],
        kdf: KdfParams,
    ) -> Result<([u8; SALT_LEN], Vec<u8>)> {
        let salt = random_bytes::<SALT_LEN>();
        let kek = argon2id(vault_passphrase, &salt, &kdf)?;
        let vault_key = Key32::random();
        let wrapped = wrap_key(&kek, &vault_key, &aad(&[AAD_VK_CUSTOM, vault_id.as_bytes()]));
        self.vaults.insert(vault_id.to_owned(), vault_key);
        Ok((salt, wrapped))
    }

    /// Opens a master-key vault so its items can be read and written.
    pub fn open_vault(&mut self, vault_id: &str, wrapped_vault_key: &[u8]) -> Result<()> {
        let vault_key = unwrap_key(&self.master, wrapped_vault_key, &aad(&[AAD_VK, vault_id.as_bytes()]))?;
        self.vaults.insert(vault_id.to_owned(), vault_key);
        Ok(())
    }

    /// Opens a custom-key vault with its own passphrase.
    pub fn open_custom_vault(
        &mut self,
        vault_id: &str,
        vault_passphrase: &[u8],
        salt: &[u8; SALT_LEN],
        kdf: KdfParams,
        wrapped_vault_key: &[u8],
    ) -> Result<()> {
        let kek = argon2id(vault_passphrase, salt, &kdf)?;
        let vault_key = unwrap_key(&kek, wrapped_vault_key, &aad(&[AAD_VK_CUSTOM, vault_id.as_bytes()]))?;
        self.vaults.insert(vault_id.to_owned(), vault_key);
        Ok(())
    }

    /// Forgets one vault's key (e.g. locking a custom-key vault again).
    pub fn close_vault(&mut self, vault_id: &str) {
        self.vaults.remove(vault_id);
    }

    /// Whether a vault is open in this keyring.
    pub fn is_vault_open(&self, vault_id: &str) -> bool {
        self.vaults.contains_key(vault_id)
    }

    fn vault_key(&self, vault_id: &str) -> Result<&Key32> {
        self.vaults.get(vault_id).ok_or(Error::VaultNotOpen)
    }

    /// Encrypts an item's content with a fresh item key.
    pub fn encrypt_item(&self, vault_id: &str, item_id: &str, plaintext: &[u8]) -> Result<SealedItem> {
        let vault_key = self.vault_key(vault_id)?;
        let item_key = Key32::random();
        let wrapped_item_key = wrap_key(vault_key, &item_key, &aad(&[AAD_IK, vault_id.as_bytes(), item_id.as_bytes()]));
        let ciphertext = seal(&item_key, plaintext, &aad(&[AAD_ITEM, vault_id.as_bytes(), item_id.as_bytes()]));
        Ok(SealedItem { wrapped_item_key, ciphertext })
    }

    /// Decrypts an item made by [`Keyring::encrypt_item`].
    pub fn decrypt_item(&self, vault_id: &str, item_id: &str, item: &SealedItem) -> Result<Vec<u8>> {
        let vault_key = self.vault_key(vault_id)?;
        let item_key = unwrap_key(
            vault_key,
            &item.wrapped_item_key,
            &aad(&[AAD_IK, vault_id.as_bytes(), item_id.as_bytes()]),
        )?;
        open(&item_key, &item.ciphertext, &aad(&[AAD_ITEM, vault_id.as_bytes(), item_id.as_bytes()]))
    }

    /// The key a `.pcipher` file in vault-key mode uses: derived from the vault key and the file's own salt.
    pub(crate) fn file_key(&self, vault_id: &str, file_salt: &[u8]) -> Result<Key32> {
        let vault_key = self.vault_key(vault_id)?;
        let mut info = INFO_FILE.to_vec();
        info.extend_from_slice(&aad(&[vault_id.as_bytes()]));
        let key = hkdf(vault_key.as_bytes(), file_salt, &info);
        info.zeroize();
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use crate::account::create_account;
    use crate::error::Error;
    use crate::keys::KdfParams;

    fn fast_kdf() -> KdfParams {
        KdfParams { memory_kib: KdfParams::MIN_MEMORY_KIB, iterations: 2, parallelism: 1 }
    }

    #[test]
    fn items_round_trip_and_are_bound_to_their_ids() {
        let mut account = create_account(b"a passphrase for tests", fast_kdf()).unwrap();
        let wrapped = account.keyring.create_vault("vault-1");
        let item = account.keyring.encrypt_item("vault-1", "item-1", b"{\"label\":\"x\"}").unwrap();
        assert_eq!(account.keyring.decrypt_item("vault-1", "item-1", &item).unwrap(), b"{\"label\":\"x\"}");

        // A server that swaps the item id or vault id gets nothing.
        assert_eq!(account.keyring.decrypt_item("vault-1", "item-2", &item).err(), Some(Error::Decrypt));

        // The vault reopens from its wrapped key after locking.
        account.keyring.close_vault("vault-1");
        assert_eq!(account.keyring.decrypt_item("vault-1", "item-1", &item).err(), Some(Error::VaultNotOpen));
        account.keyring.open_vault("vault-1", &wrapped).unwrap();
        assert!(account.keyring.decrypt_item("vault-1", "item-1", &item).is_ok());
        assert!(account.keyring.open_vault("vault-2", &wrapped).is_err());
    }

    #[test]
    fn custom_vaults_need_their_own_passphrase() {
        let mut account = create_account(b"account passphrase 1", fast_kdf()).unwrap();
        let (salt, wrapped) = account.keyring.create_custom_vault("v", b"vault secret words", fast_kdf()).unwrap();
        account.keyring.close_vault("v");
        assert!(account.keyring.open_vault("v", &wrapped).is_err());
        assert!(account.keyring.open_custom_vault("v", b"wrong words here", &salt, fast_kdf(), &wrapped).is_err());
        account.keyring.open_custom_vault("v", b"vault secret words", &salt, fast_kdf(), &wrapped).unwrap();
        assert!(account.keyring.is_vault_open("v"));
    }
}
