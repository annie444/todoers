//! OPAQUE server primitives.
//!
//! Defines the server's OPAQUE cipher suite and the `OpaqueServer` wrapper around
//! the long-lived `ServerSetup` (OPRF seed + server keypair) that registration
//! and login both run against. Generated once and persisted; regenerating it
//! invalidates every stored password file.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use old_rand_core::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerRegistration, ServerSetup,
};
use tokio::{fs, task};

use todoers_types::SharedCipherSuite;

pub type Setup = ServerSetup<SharedCipherSuite>;
pub type PasswordFile = ServerRegistration<SharedCipherSuite>;
pub type Login = ServerLogin<SharedCipherSuite>;
pub type Finalization = CredentialFinalization<SharedCipherSuite>;
pub type RegistrationReq = RegistrationRequest<SharedCipherSuite>;
pub type Registration = ServerRegistration<SharedCipherSuite>;
pub type RegistrationUp = RegistrationUpload<SharedCipherSuite>;
pub type CredentialReq = CredentialRequest<SharedCipherSuite>;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct OpaqueServer {
    inner: Arc<Setup>,
}

impl OpaqueServer {
    /// Generate a brand-new server setup. Call this ONCE, ever, then persist the
    /// serialized bytes. Re-generating throws away every existing password file.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            inner: Arc::new(Setup::new(&mut rng)),
        }
    }

    /// Serialize for storage. `.serialize()` returns a GenericArray; `.to_vec()`
    /// gives you the bytes to drop into your secret store.
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }

    pub fn load(bytes: &[u8]) -> anyhow::Result<Self> {
        let setup = Setup::deserialize(bytes).context("corrupt server setup")?;
        Ok(Self {
            inner: Arc::new(setup),
        })
    }

    /// Load from a secret path, generating + writing on first run. In a real
    /// deployment this is your secrets manager / SOPS-decrypted file, not a plain
    /// path — shown here as the shape, not the recommendation.
    pub async fn load_or_init<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        match fs::read(path.as_ref()).await {
            Ok(bytes) => Self::load(&bytes),
            Err(_) => {
                let setup = task::spawn_blocking(Self::generate).await?;
                if let Some(parent) = path.as_ref().parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent)
                            .await
                            .context("cannot create parent directory for server setup")?;
                    } else if !parent.is_dir() {
                        return Err(anyhow::anyhow!(
                            "parent path for server setup is not a directory"
                        ));
                    }
                } else {
                    return Err(anyhow::anyhow!("invalid path for server setup"));
                };
                fs::write(path.as_ref(), setup.serialize())
                    .await
                    .context("cannot persist server setup")?;
                Ok(setup)
            }
        }
    }

    pub fn get(&self) -> &Setup {
        &self.inner
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl OpaqueServer {
        pub fn new_for_test() -> Self {
            Self::load(&[
                51, 97, 224, 171, 243, 182, 168, 86, 179, 61, 222, 62, 110, 165, 60, 179, 71, 191,
                52, 45, 125, 91, 232, 253, 188, 136, 62, 41, 3, 147, 126, 20, 14, 108, 239, 115, 9,
                230, 183, 118, 185, 154, 164, 221, 22, 180, 25, 173, 190, 242, 16, 21, 194, 206,
                214, 219, 83, 13, 82, 244, 4, 114, 168, 199, 65, 236, 190, 242, 112, 8, 155, 18,
                157, 6, 198, 42, 193, 97, 164, 202, 68, 89, 182, 20, 184, 98, 30, 199, 143, 82, 20,
                14, 109, 160, 109, 14, 56, 56, 146, 156, 169, 138, 216, 77, 122, 144, 89, 239, 254,
                83, 113, 87, 78, 160, 86, 46, 237, 241, 57, 135, 54, 111, 22, 175, 79, 73, 254, 96,
            ])
            .unwrap()
        }
    }

    #[test]
    fn serialize_round_trip() {
        let server = OpaqueServer::generate();
        let bytes = server.serialize();
        let deserialized = OpaqueServer::load(&bytes).expect("deserialization failed");
        assert_eq!(
            server.get().keypair().private(),
            deserialized.get().keypair().private()
        );
        assert_eq!(
            server.get().keypair().public(),
            deserialized.get().keypair().public()
        );
    }
}
