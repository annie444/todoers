use hybrid_array::ArrayN;
use keyring_core::Entry;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x_wing::{CIPHERTEXT_SIZE, ENCAPSULATION_KEY_SIZE};

use crate::error::TodoersResult;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;
pub mod wrap;

pub mod hex_ciphertext {
    use hybrid_array::ArrayN;
    use serde::{Deserialize, Deserializer, Serializer};
    use x_wing::CIPHERTEXT_SIZE;

    pub fn serialize<S: Serializer>(
        bytes: &ArrayN<u8, CIPHERTEXT_SIZE>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Box<ArrayN<u8, CIPHERTEXT_SIZE>>, D::Error> {
        let s = String::deserialize(d)?;
        let mut slice = [0u8; CIPHERTEXT_SIZE];
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        slice.copy_from_slice(&bytes);
        Ok(Box::new(slice.into()))
    }
}

pub mod hex_enc_key {
    use hybrid_array::ArrayN;
    use serde::{Deserialize, Deserializer, Serializer};
    use x_wing::ENCAPSULATION_KEY_SIZE;

    pub fn serialize<S: Serializer>(
        bytes: &ArrayN<u8, ENCAPSULATION_KEY_SIZE>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Box<ArrayN<u8, ENCAPSULATION_KEY_SIZE>>, D::Error> {
        let s = String::deserialize(d)?;
        let mut slice = [0u8; ENCAPSULATION_KEY_SIZE];
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        slice.copy_from_slice(&bytes);
        Ok(Box::new(slice.into()))
    }
}

pub mod hex16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let mut slice = [0u8; 16];
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        slice.copy_from_slice(&bytes);
        Ok(slice)
    }
}

pub mod hex24 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 24], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 24], D::Error> {
        let s = String::deserialize(d)?;
        let mut slice = [0u8; 24];
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        slice.copy_from_slice(&bytes);
        Ok(slice)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum RecipientEnvelope {
    DeviceXWing {
        id: Uuid,
        label: String,
        backend: DeviceBackend,
        // public key is safe to store
        #[serde(with = "hex_enc_key")]
        encapsulation_key: Box<ArrayN<u8, ENCAPSULATION_KEY_SIZE>>,
        // KEM ciphertext
        #[serde(with = "hex_ciphertext")]
        kem_ciphertext: Box<ArrayN<u8, CIPHERTEXT_SIZE>>,
        // encrypted SQLCipher raw key
        wrapped_key: Vec<u8>,
        #[serde(with = "hex24")]
        nonce: [u8; 24],
        #[serde(with = "hex16")]
        kek_salt: [u8; 16],
    },
    Password {
        id: Uuid,
        label: String,
        #[serde(with = "hex16")]
        argon2_salt: [u8; 16],
        argon2_memory_cost_kib: u32,
        argon2_time_cost: u32,
        argon2_parallelism: u32,
        wrapped_key: Vec<u8>,
        #[serde(with = "hex24")]
        nonce: [u8; 24],
        #[serde(with = "hex16")]
        kek_salt: [u8; 16],
    },
}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Copy)]
pub enum DeviceBackend {
    MacosKeychain,
    LinuxSecretService,
    LinuxTpm2,
    WindowsCredentialManager,
}

pub trait DeviceKeyStore {
    fn backend(&self) -> DeviceBackend;
    fn store_key(&self, name: &str, key: &[u8]) -> TodoersResult<()> {
        let entry = Entry::new(env!("CARGO_PKG_NAME"), name)?;
        entry.set_secret(key)?;
        Ok(())
    }

    fn get_key(&self, name: &str) -> TodoersResult<Vec<u8>> {
        let entry = Entry::new(env!("CARGO_PKG_NAME"), name)?;
        let secret = entry.get_secret()?;
        Ok(secret)
    }
}

pub fn select_device_store() -> TodoersResult<impl DeviceKeyStore> {
    #[cfg(all(target_os = "macos", not(test)))]
    let store = macos::MacosKeychain::new()?;
    #[cfg(all(target_os = "linux", not(test)))]
    let store = linux::LinuxSecretService::new()?;
    #[cfg(test)]
    let store = MockKeychain::new()?;
    Ok(store)
}

/// In-memory device store used in tests.
///
/// Registers `keyring_core`'s mock store as the process-wide default exactly once.
/// We deliberately do *not* unset it on drop: the mock store must outlive any single
/// `MockKeychain` so that a key written during `create_new_database_keys` is still
/// present when a later `unlock_with_device` constructs a fresh `MockKeychain`.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct MockKeychain;

#[cfg(test)]
impl MockKeychain {
    pub fn new() -> TodoersResult<Self> {
        use std::sync::Once;
        static SET_STORE: Once = Once::new();
        SET_STORE.call_once(|| {
            let store =
                keyring_core::mock::Store::new().expect("failed to build keyring_core mock store");
            keyring_core::set_default_store(store);
        });
        Ok(MockKeychain)
    }
}

#[cfg(test)]
impl DeviceKeyStore for MockKeychain {
    // Reuse an existing backend so the recipient created here matches the one
    // `unlock_with_device` looks up; the value is irrelevant to the mock store.
    fn backend(&self) -> DeviceBackend {
        DeviceBackend::MacosKeychain
    }
}
