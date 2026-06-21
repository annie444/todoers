//! In-memory session state: the unlocked identity plus the class-3 DEK map.
//!
//! Unwrapped DEKs and private keys are **never** written to disk (see the
//! at-rest notes in `db/migrations/0001_init.sql`). At unlock we rehydrate the
//! per-`(list, epoch)` DEK map by `open_sealed`-ing the cached `key_slots`, and
//! it lives here in process memory only for the life of the session.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use todoers_types::{Ed25519Pub, Epoch, ListId, MemberId, X25519Pub};

use crate::auth::UnlockedKeys;
use crate::crypto;
use crate::db::Db;

/// The decrypted identity + the DEKs needed to read/write list updates.
pub struct Session {
    member_id: MemberId,
    identity_secret: Zeroizing<[u8; 32]>,
    identity_pub: X25519Pub,
    signing_seed: Zeroizing<[u8; 32]>,
    signing_pub: Ed25519Pub,
    token: String,
    /// `(list, epoch) -> DEK`. Class-3: memory only.
    deks: HashMap<(ListId, Epoch), Zeroizing<[u8; 32]>>,
}

impl Session {
    /// Build a session from freshly-unlocked keys (copies the secret material).
    pub fn new(keys: &UnlockedKeys) -> Self {
        Self {
            member_id: keys.member_id,
            identity_secret: Zeroizing::new(keys.identity_secret),
            identity_pub: keys.identity_pub,
            signing_seed: Zeroizing::new(keys.signing_seed),
            signing_pub: keys.signing_pub,
            token: keys.token.clone(),
            deks: HashMap::new(),
        }
    }

    /// Open every cached wrapped DEK into the in-memory map. Slots that fail to
    /// unseal (e.g. a retired epoch sealed to a different key) are skipped.
    #[tracing::instrument(skip(self, db))]
    pub async fn rehydrate(&mut self, db: &Db) -> anyhow::Result<()> {
        for slot in db.load_key_slots().await? {
            if let Ok(dek) =
                crypto::open_sealed(&slot.wrapped_dek, &self.identity_pub, &self.identity_secret)
            {
                self.deks
                    .insert((slot.list_id, slot.epoch), Zeroizing::new(dek));
            }
        }
        Ok(())
    }

    /// The DEK for a `(list, epoch)`, if known.
    pub fn dek(&self, list_id: ListId, epoch: Epoch) -> Option<[u8; 32]> {
        self.deks.get(&(list_id, epoch)).map(|d| **d)
    }

    /// Record a DEK (e.g. just after creating a list or rotating on removal).
    pub fn insert_dek(&mut self, list_id: ListId, epoch: Epoch, dek: [u8; 32]) {
        self.deks.insert((list_id, epoch), Zeroizing::new(dek));
    }

    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    pub fn identity_pub(&self) -> X25519Pub {
        self.identity_pub
    }

    pub fn signing_pub(&self) -> Ed25519Pub {
        self.signing_pub
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Reconstruct the Ed25519 signing key from its seed (for `produce_update`).
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing_seed)
    }
}
