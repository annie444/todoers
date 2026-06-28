//! In-memory session state: the unlocked identity plus the class-3 DEK map.
//!
//! Unwrapped DEKs and private keys are **never** written to disk (see the
//! at-rest notes in `db/migrations/0001_init.sql`). At unlock we rehydrate the
//! per-`(list, epoch)` DEK map by `open_sealed`-ing the cached `key_slots`, and
//! it lives here in process memory only for the life of the session.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;

use todoers_types::{
    Dek, Ed25519Pub, Ed25519Signing, Epoch, ListId, MemberId, X25519Pub, X25519Secret,
};

use crate::auth::UnlockedKeys;
use crate::crypto;
use crate::db::Db;
use crate::error::TodoersResult;

/// The decrypted identity + the DEKs needed to read/write list updates.
pub struct Session {
    member_id: MemberId,
    identity_secret: X25519Secret,
    identity_pub: X25519Pub,
    signing_seed: Ed25519Signing,
    signing_pub: Ed25519Pub,
    token: String,
    /// `(list, epoch) -> DEK`. Class-3: memory only.
    deks: HashMap<(ListId, Epoch), Dek>,
}

impl Session {
    /// Build a session from freshly-unlocked keys (copies the secret material).
    pub fn new(keys: &UnlockedKeys) -> Self {
        Self {
            member_id: keys.member_id,
            identity_secret: keys.identity_secret.clone(),
            identity_pub: keys.identity_pub.clone(),
            signing_seed: keys.signing_seed.clone(),
            signing_pub: keys.signing_pub.clone(),
            token: keys.token.clone(),
            deks: HashMap::new(),
        }
    }

    /// Open every cached wrapped DEK into the in-memory map. Slots that fail to
    /// unseal (e.g. a retired epoch sealed to a different key) are skipped.
    #[tracing::instrument(skip(self, db))]
    pub async fn rehydrate(&mut self, db: &Db) -> TodoersResult<()> {
        for slot in db.load_key_slots().await? {
            match crypto::open_sealed(&slot.wrapped_dek, &self.identity_pub, &self.identity_secret)
            {
                Ok(dek) => {
                    self.deks.insert((slot.list_id, slot.epoch), dek);
                }
                // A slot that won't unseal means the current identity key can't open
                // a DEK it should (e.g. a stale slot sealed to a now-defunct key, or a
                // retired epoch). Skipping it silently surfaces later as the opaque
                // "no DEK for current epoch"; log it so the cause is diagnosable.
                Err(e) => tracing::warn!(
                    list_id = ?slot.list_id, epoch = ?slot.epoch, error = ?e,
                    "rehydrate: key slot failed to unseal; DEK skipped"
                ),
            }
        }
        Ok(())
    }

    /// The DEK for a `(list, epoch)`, if known.
    pub fn dek(&self, list_id: ListId, epoch: Epoch) -> Option<Dek> {
        self.deks.get(&(list_id, epoch)).cloned()
    }

    /// Record a DEK (e.g. just after creating a list or rotating on removal).
    pub fn insert_dek(&mut self, list_id: ListId, epoch: Epoch, dek: Dek) {
        self.deks.insert((list_id, epoch), dek);
    }

    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    pub fn identity_pub(&self) -> X25519Pub {
        self.identity_pub.clone()
    }

    pub fn signing_pub(&self) -> Ed25519Pub {
        self.signing_pub.clone()
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Reconstruct the Ed25519 signing key from its seed (for `produce_update`).
    pub fn signing_key(&self) -> SigningKey {
        (&self.signing_seed).into()
    }
}
