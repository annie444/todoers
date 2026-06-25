//! keyring-core credential store backed by the TPM2 sealed store in `tpm`.
//!
//! Two traits, two objects:
//!   * `Store` implements `CredentialStoreApi` — the factory. One per process,
//!     registered via `keyring_core::set_default_store`. Owns the shared TPM
//!     state (context, persistent SRK, authorizing key, the store-global sealed
//!     DEK, config).
//!   * `TpmCredential` implements `CredentialApi` — one per entry. Holds a
//!     handle back to the shared store plus its `{service, user}` identity,
//!     which maps deterministically to an on-disk blob path.
//!
//! # The three design decisions worth understanding
//!
//! 1. **One sealed DEK for the whole store, not one per entry.** TPM unseal is
//!    slow and the sealed-object sensitive area is tiny. So we seal a single
//!    32-byte DEK once (store-global), cache the unlocked copy, and
//!    XChaCha20-Poly1305-wrap each entry's secret under it. `set_secret` =
//!    wrap+write a file; `get_secret` = read file+unwrap. The TPM is touched
//!    once per process cold-start (the unseal), then the keyutils/in-memory
//!    cache serves everything else.
//!
//! 2. **`build` must NOT touch the TPM.** keyring-core's model (like the native
//!    stores) is that building a credential is cheap bookkeeping; the store is
//!    only mutated when a secret is *written*. So `build` just constructs a
//!    `TpmCredential` value. All sealing/unsealing happens in set/get_secret.
//!
//! 3. **Thread-safety is mandatory and the TPM context is `!Sync`.** keyring-core
//!    requires `Store` and `Credential` to be `Send + Sync`. A tss-esapi
//!    `Context` is a handle to one device and is not safe for concurrent use, so
//!    it lives behind a `Mutex` inside the shared `StoreInner`; every TPM op
//!    takes the lock. Cheap, since the in-kernel RM serializes anyway.
//!
//! NOTE ON SIGNATURES: `CredentialApi` below matches the published trait. The
//! `CredentialStoreApi` method set is the less-stable half of the SPI — verify
//! `build`/`vendor`/`id`/`search`/`get_credential` against your pinned
//! `keyring_core::api` rustdoc and the `sample` store, and adjust Box/Arc return
//! types to match.

use std::any::Any;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use keyring_core::CredentialPersistence;
use keyring_core::api::{CredentialApi, CredentialStoreApi};
use keyring_core::{Credential, Error as KeyringError, Result as KeyringResult};

use tss_esapi::{
    Context,
    handles::KeyHandle,
    structures::{Private, Public, Signature},
};
use zeroize::Zeroizing;

use super::tpm::{self, TpmStoreError};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Everything the store needs, shared (via `Arc`) between the `Store` factory
/// and every `TpmCredential` it hands out.
struct StoreInner {
    /// tss-esapi Context is `!Sync`; serialize all TPM access through this lock.
    tpm: Mutex<Context>,
    /// Persistent SRK (parent for the sealed DEK). Provisioned at startup.
    srk: KeyHandle,
    /// Public half of the offline authorizing key (for PolicyAuthorize unseal).
    signing_pub: Public,
    /// The store-global sealed DEK blobs `(private, public)`, lazily created on
    /// first write and persisted to disk. `None` until the first `set_secret`.
    sealed_dek: Mutex<Option<(Private, Public)>>,
    /// Unlocked DEK cache. Mirror of what also lives in the kernel session
    /// keyring; `None` until first unseal/create this process.
    dek_cache: Mutex<Option<Zeroizing<[u8; 32]>>>,
    cfg: StoreConfig,
}

#[derive(Clone)]
pub struct StoreConfig {
    /// Directory holding the sealed-DEK blob and the per-entry wrapped files.
    pub data_dir: PathBuf,
    /// Approved PCR policy digest + signature for the *current* expected PCR
    /// state, regenerated offline on OS updates. Non-secret deployment data.
    pub approved_policy: tss_esapi::structures::Digest,
    pub policy_signature: Signature,
}

/// The factory. Register with `keyring_core::set_default_store(Store::new(cfg)?)`.
pub struct Store {
    inner: Arc<StoreInner>,
}

impl Store {
    /// Open the TPM, provision/adopt the persistent SRK, and load the authorizing
    /// public key. Returns an `Arc<Self>` because keyring-core shares the store.
    pub fn new(cfg: StoreConfig, signing_pub: Public) -> KeyringResult<Arc<Self>> {
        let mut ctx = tpm::open_context().map_err(to_keyring_err)?;
        let srk = tpm::provision_srk(&mut ctx).map_err(to_keyring_err)?;

        // Adopt an existing sealed DEK blob from disk if present.
        let sealed_dek = load_sealed_dek(&cfg.data_dir);

        Ok(Arc::new(Store {
            inner: Arc::new(StoreInner {
                tpm: Mutex::new(ctx),
                srk,
                signing_pub,
                sealed_dek: Mutex::new(sealed_dek),
                dek_cache: Mutex::new(None),
                cfg,
            }),
        }))
    }
}

// ---------------------------------------------------------------------------
// CredentialStoreApi  (verify exact signatures against your keyring-core pin)
// ---------------------------------------------------------------------------

impl CredentialStoreApi for Store {
    /// Vendor/id strings are used by keyring-core for debug + ambiguity reports.
    fn vendor(&self) -> String {
        "tpm2-sealed-store (PolicyAuthorize/signed-PCR)".to_string()
    }

    fn id(&self) -> String {
        format!("tpm2-sealed-store@{}", self.inner.cfg.data_dir.display())
    }

    /// Produce a credential (a "specifier") for a service/user. Cheap: no TPM,
    /// no disk write. `modifiers` is the map that replaced the old `target`
    /// argument; we ignore it here but you could honor e.g. a `target` override.
    fn build(
        &self,
        service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> KeyringResult<Box<Credential>> {
        Ok(TpmCredential {
            inner: Arc::clone(&self.inner),
            service: service.to_string(),
            user: user.to_string(),
        })
    }

    /// On-disk, survives reboot. (Contrast the keyutils stores, which return a
    /// volatile variant.)
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    // Likely also required/overridable on your pin — stub or implement per rustdoc:
    //   fn get_credential(&self, ...) -> ...      // wrapper resolution
    //   fn search(&self, spec: &HashMap<..>) -> ...  // optional bulk lookup
    //   fn debug_fmt(&self, f: &mut Formatter<'_>) -> fmt::Result
}

// ---------------------------------------------------------------------------
// CredentialApi  (these signatures match the published trait)
// ---------------------------------------------------------------------------

pub struct TpmCredential {
    inner: Arc<StoreInner>,
    service: String,
    user: String,
}

impl CredentialApi for TpmCredential {
    /// Wrap `secret` under the store DEK and persist it. First write in the
    /// store's life lazily creates + seals the DEK.
    fn set_secret(&self, secret: &[u8]) -> KeyringResult<()> {
        let dek = self.inner.ensure_dek().map_err(to_keyring_err)?;
        let blob = aead_wrap(&dek, secret).map_err(to_keyring_err)?;
        write_entry(&self.inner.cfg.data_dir, &self.service, &self.user, &blob)
            .map_err(to_keyring_err)
    }

    /// Read the entry's blob and unwrap it. `NoEntry` if it doesn't exist.
    fn get_secret(&self) -> KeyringResult<Vec<u8>> {
        let blob = read_entry(&self.inner.cfg.data_dir, &self.service, &self.user)
            .map_err(|_| KeyringError::NoEntry)?;
        let dek = self.inner.dek_plaintext().map_err(to_keyring_err)?;
        aead_unwrap(&dek, &blob).map_err(to_keyring_err)
    }

    /// Forget this entry. Does NOT destroy the sealed DEK — other entries share it.
    fn delete_credential(&self) -> KeyringResult<()> {
        delete_entry(&self.inner.cfg.data_dir, &self.service, &self.user)
            .map_err(|_| KeyringError::NoEntry)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// DEK lifecycle — the bridge to tpm
// ---------------------------------------------------------------------------

impl StoreInner {
    /// Return the unlocked DEK, creating+sealing one on the very first write.
    fn ensure_dek(&self) -> Result<Zeroizing<[u8; 32]>, TpmStoreError> {
        if let Some(dek) = self.dek_cache.lock().unwrap().clone() {
            return Ok(dek);
        }
        let mut sealed = self.sealed_dek.lock().unwrap();
        if sealed.is_none() {
            // First ever write: generate a DEK, seal it under the SRK with the
            // PolicyAuthorize authPolicy, persist the blobs.
            let dek = Zeroizing::new(random_dek());
            let mut ctx = self.tpm.lock().unwrap();

            let (_sig_handle, key_name) =
                tpm::load_authorizing_key(&mut ctx, self.signing_pub.clone())?;
            let auth_policy = tpm::authorized_policy_digest(&mut ctx, &key_name)?;
            let blobs = tpm::seal(&mut ctx, self.srk, auth_policy, dek.as_ref())?;

            persist_sealed_dek(&self.cfg.data_dir, &blobs)
                .map_err(|e| TpmStoreError::Convert(e.to_string()))?;
            *sealed = Some(blobs);
            *self.dek_cache.lock().unwrap() = Some(dek.clone());
            // TODO: also stash `dek` in the kernel session keyring here.
            return Ok(dek);
        }
        drop(sealed);
        self.dek_plaintext()
    }

    /// Get the unlocked DEK: in-memory cache -> (TODO keyutils) -> TPM unseal.
    fn dek_plaintext(&self) -> Result<Zeroizing<[u8; 32]>, TpmStoreError> {
        if let Some(dek) = self.dek_cache.lock().unwrap().clone() {
            return Ok(dek);
        }
        // TODO: check the kernel session keyring before falling through to unseal.

        let (private, public) = self
            .sealed_dek
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| TpmStoreError::Convert("no sealed DEK on disk".into()))?;

        let mut ctx = self.tpm.lock().unwrap();
        let secret = tpm::unseal(
            &mut ctx,
            self.srk,
            private,
            public,
            self.signing_pub.clone(),
            self.cfg.approved_policy.clone(),
            self.cfg.policy_signature.clone(),
        )?;

        let mut dek = [0u8; 32];
        let bytes = secret.as_bytes();
        if bytes.len() != 32 {
            return Err(TpmStoreError::Convert("unsealed DEK wrong length".into()));
        }
        dek.copy_from_slice(bytes);
        let dek = Zeroizing::new(dek);
        *self.dek_cache.lock().unwrap() = Some(dek.clone());
        // TODO: mirror into the kernel session keyring.
        Ok(dek)
    }
}

// ---------------------------------------------------------------------------
// glue you fill in (your existing crypto + a small on-disk format)
// ---------------------------------------------------------------------------

fn to_keyring_err(e: TpmStoreError) -> KeyringError {
    // Map into keyring-core's Error::PlatformFailure (or your chosen variant);
    // check the exact constructor on your pin.
    KeyringError::PlatformFailure(Box::new(e))
}

fn random_dek() -> [u8; 32] {
    unimplemented!("CSPRNG (getrandom / OsRng)")
}
fn aead_wrap(_dek: &[u8; 32], _pt: &[u8]) -> Result<Vec<u8>, TpmStoreError> {
    unimplemented!("XChaCha20-Poly1305 seal; prepend nonce")
}
fn aead_unwrap(_dek: &[u8; 32], _blob: &[u8]) -> Result<Vec<u8>, TpmStoreError> {
    unimplemented!("XChaCha20-Poly1305 open")
}

fn entry_path(dir: &std::path::Path, service: &str, user: &str) -> PathBuf {
    // Hash {service,user} into a stable filename; don't put raw identities in
    // path components. e.g. dir/blake3(service\0user).bin
    let _ = (service, user);
    dir.join("entry.bin")
}
fn write_entry(
    _dir: &std::path::Path,
    _s: &str,
    _u: &str,
    _blob: &[u8],
) -> Result<(), TpmStoreError> {
    unimplemented!()
}
fn read_entry(_dir: &std::path::Path, _s: &str, _u: &str) -> Result<Vec<u8>, TpmStoreError> {
    unimplemented!()
}
fn delete_entry(_dir: &std::path::Path, _s: &str, _u: &str) -> Result<(), TpmStoreError> {
    unimplemented!()
}
fn load_sealed_dek(_dir: &std::path::Path) -> Option<(Private, Public)> {
    None
}
fn persist_sealed_dek(_dir: &std::path::Path, _blobs: &(Private, Public)) -> std::io::Result<()> {
    unimplemented!()
}

// Usage:
//   let store = Store::new(cfg, signing_pub)?;
//   keyring_core::set_default_store(store);
//   let entry = keyring_core::Entry::new("my-tui", "api-token")?;
//   entry.set_secret(token)?;          // seals DEK on first write, wraps token
//   let token = entry.get_secret()?;   // unseals DEK once, unwraps
