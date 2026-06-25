use std::sync::Arc;

use windows_native_keyring_store::Store;

use super::backend::{DeviceBackend, DeviceKeyStore};
use crate::error::TodoersResult;

#[derive(Debug, Clone)]
pub struct MacosKeychain;

impl DeviceKeyStore for MacosKeychain {
    type CredentialStore = Store;
    fn backend() -> DeviceBackend {
        DeviceBackend::WindowsCredentialManager
    }

    fn store() -> TodoersResult<Arc<Store>> {
        let store = Store::new()?;
        Ok(store)
    }
}
