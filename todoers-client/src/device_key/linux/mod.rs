use zbus_secret_service_keyring_store::Store;

use super::{DeviceBackend, DeviceKeyStore};
use crate::error::TodoersResult;

#[cfg(feature = "tpm")]
pub mod tpm;

#[derive(Debug, Clone)]
pub struct LinuxSecretService;

impl LinuxSecretService {
    pub fn new() -> TodoersResult<Self> {
        let store = Store::new()?;
        keyring_core::set_default_store(store.clone());
        Ok(LinuxSecretService)
    }
}

impl DeviceKeyStore for LinuxSecretService {
    fn backend(&self) -> DeviceBackend {
        DeviceBackend::LinuxSecretService
    }
}

impl Drop for LinuxSecretService {
    fn drop(&mut self) {
        keyring_core::unset_default_store();
    }
}
