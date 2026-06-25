use apple_native_keyring_store::keychain::Store;

use super::{DeviceBackend, DeviceKeyStore};
use crate::error::TodoersResult;

#[derive(Debug, Clone)]
pub struct MacosKeychain;

impl MacosKeychain {
    pub fn new() -> TodoersResult<Self> {
        let store = Store::new()?;
        keyring_core::set_default_store(store.clone());
        Ok(MacosKeychain)
    }
}

impl DeviceKeyStore for MacosKeychain {
    fn backend(&self) -> DeviceBackend {
        DeviceBackend::MacosKeychain
    }
}

impl Drop for MacosKeychain {
    fn drop(&mut self) {
        keyring_core::unset_default_store();
    }
}
