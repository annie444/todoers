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
use oldsha2::Sha512;
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::key_exchange::group::ristretto255::Ristretto255;
use opaque_ke::key_exchange::tripledh::TripleDh;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerRegistration, ServerSetup,
};
use tokio::{fs, task};

#[derive(Debug)]
pub struct ServerCipherSuite;

impl CipherSuite for ServerCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub type Setup = ServerSetup<ServerCipherSuite>;
pub type PasswordFile = ServerRegistration<ServerCipherSuite>;
pub type Login = ServerLogin<ServerCipherSuite>;
pub type Finalization = CredentialFinalization<ServerCipherSuite>;
pub type RegistrationReq = RegistrationRequest<ServerCipherSuite>;
pub type Registration = ServerRegistration<ServerCipherSuite>;
pub type RegistrationUp = RegistrationUpload<ServerCipherSuite>;
pub type CredentialReq = CredentialRequest<ServerCipherSuite>;

// TODO: the b64 encoding is just for human convenience. Use bytes instead.
//
// macro_rules! impl_b64 {
//     ($t:ty, $mod:ident) => {
//         pub mod $mod {
//             use base64::{Engine as _, engine::general_purpose::STANDARD};
//             use serde::{Deserialize, Deserializer, Serializer};
//
//             pub fn serialize<S: Serializer>(data: &$t, s: S) -> Result<S::Ok, S::Error> {
//                 let bytes = data.serialize().to_vec();
//                 s.serialize_str(&STANDARD.encode(bytes))
//             }
//
//             pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<$t, D::Error> {
//                 let s = String::deserialize(d)?;
//                 let data = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
//                 <$t>::deserialize(&data).map_err(serde::de::Error::custom)
//             }
//         }
//     };
// }

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
