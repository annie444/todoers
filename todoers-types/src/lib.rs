//! Wire + key schema for a zero-knowledge, shareable todo list.
//!
//! Byte fields are base64-encoded so the API is JSON-inspectable for a scaffold.
//! In production you'd likely switch the update path to `application/octet-stream`
//! carrying the client's postcard-serialized `UpdatePayload` directly.
//!
//! The `signing_view` here MUST match the client's canonical encoding exactly,
//! or server-side verification will reject valid updates.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

pub type HmacSha256 = Hmac<Sha256>;
pub const DEK_LEN: usize = 32;

/// Random 16-byte list identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListId(pub [u8; 16]);

/// Stable per-user id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberId(pub [u8; 16]);

impl MemberId {
    /// The raw 16 bytes — used directly as OPAQUE's `credential_identifier` on
    /// both the client and the server, so the two MUST agree byte-for-byte.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Derive the stable member id from the X25519 identity public key.
    ///
    /// This is the canonical binding both sides rely on: the server computes it
    /// itself from the uploaded `identity_pub` (so a client can never claim a
    /// member id that doesn't match its key), and the client computes the same
    /// value to address co-members. It MUST be:
    ///   - a one-way hash of `identity_pub.0` (32 bytes in),
    ///   - domain-separated (a fixed personalization/tag), so this digest can
    ///     never collide with a hash computed for another purpose over the same
    ///     key bytes,
    ///   - truncated deterministically to the first 16 bytes.
    ///
    /// `sha2` is available in this crate (workspace dep). A sketch:
    /// ```ignore
    /// use sha2::{Digest, Sha256};
    /// let digest = Sha256::new()
    ///     .chain_update(b"todoers:member-id:v1")   // domain separation
    ///     .chain_update(identity_pub.0)
    ///     .finalize();
    /// let mut id = [0u8; 16];
    /// id.copy_from_slice(&digest[..16]);
    /// MemberId(id)
    /// ```
    pub fn from_identity_pub(identity_pub: &X25519Pub) -> Self {
        let mut id = [0u8; 16];
        let mac = HmacSha256::new_from_slice(b"todoers:member-id:identity:v0001")
            .expect("Key is the right size for HMAC-SHA256") // 32 bytes, guaranteed by the type system
            .chain_update(identity_pub.0)
            .finalize()
            .into_bytes()
            .to_vec();
        id.copy_from_slice(&mac[..16]);
        Self(id)
    }
}

/// X25519 public key — DEKs are sealed *to* this.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519Pub(pub [u8; 32]);

/// Ed25519 public key — update signatures are verified against this.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Pub(pub [u8; 32]);

/// DEK generation. Bumped on every membership-driven rotation. Each update
/// records the epoch it was encrypted under so readers pick the right key.
pub type Epoch = u32;

#[derive(Zeroize, Clone, PartialEq, Eq)]
#[zeroize(drop)] // Automatically zeroes out when dropped
pub struct Dek {
    inner: Box<[u8; 32]>,
}

impl Dek {
    pub fn new(key: [u8; DEK_LEN]) -> Self {
        Self {
            inner: Box::new(key),
        }
    }

    pub fn new_with_mut<F>(f: F) -> Self
    where
        F: FnOnce(&mut [u8; DEK_LEN]),
    {
        let mut inner = [0u8; DEK_LEN];
        f(&mut inner);
        Self {
            inner: Box::new(inner),
        }
    }

    pub fn new_with<F>(f: F) -> Self
    where
        F: FnOnce() -> [u8; DEK_LEN],
    {
        Self {
            inner: Box::new(f()),
        }
    }

    pub fn try_new_with<F, E>(f: F) -> Result<Self, E>
    where
        F: FnOnce() -> Result<[u8; DEK_LEN], E>,
        E: Clone,
    {
        Ok(Self {
            inner: Box::new(f()?),
        })
    }

    pub fn get(&self) -> &[u8; DEK_LEN] {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut [u8; DEK_LEN] {
        &mut self.inner
    }
}

// ---------------------------------------------------------------------------
// Update envelope — the unit the server stores and relays.
// ---------------------------------------------------------------------------

/// What the author actually produces and signs. `seq` is deliberately NOT in
/// here: the server assigns storage order on append, and CRDT merge is
/// order-independent, so the author never needs to know its slot in advance.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdatePayload {
    pub version: u8,
    pub list_id: ListId,
    pub epoch: Epoch,
    pub author: MemberId,
    /// Per-update random XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// AEAD(DEK[epoch], nonce, plaintext = Loro binary update, aad = binding).
    pub ciphertext: Vec<u8>,
    /// Ed25519 over `signing_view(&payload)` (encrypt-then-sign).
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
}

/// What lands in the log. `seq` is server-assigned, unsigned, untrusted-but-
/// fine: a blind relay can reorder or withhold, but reorder is harmless to a
/// CRDT and withholding is an availability property you can't take from a
/// relay anyway. Clients detect real gaps via the per-author counters baked
/// into the decrypted CRDT updates.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredUpdate {
    pub seq: u64,
    pub payload: UpdatePayload,
}

// ---------------------------------------------------------------------------
// List metadata — identity, roles, and wrapped DEKs (separated by concern).
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(sqlx::Type))]
#[cfg_attr(
    feature = "postgres",
    sqlx(type_name = "member_role", rename_all = "lowercase")
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Public identity of one collaborator. None of this is secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: MemberId,
    pub identity_pub: X25519Pub, // seal DEKs to this
    pub signing_pub: Ed25519Pub, // verify their updates with this
    pub role: Role,
}

/// One wrapped copy of a DEK: `seal_to(dek_for_epoch, member.identity_pub)`.
/// Keyed by (epoch, member) so a member coming online can fetch exactly the
/// keys they need for the epochs still present in the log.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeySlot {
    pub epoch: Epoch,
    pub member: MemberId,
    /// Anonymous sealed box: only the holder of the matching X25519 secret
    /// can open it, and it carries no sender identity.
    pub wrapped_dek: Vec<u8>,
}

/// The full per-list metadata blob. Lives on the server; fully non-secret
/// EXCEPT `encrypted_name`, because a list's title leaks intent.
#[derive(Clone, Serialize, Deserialize)]
pub struct ListMetadata {
    pub version: u8,
    pub list_id: ListId,
    /// DEK generation new updates are written under.
    pub current_epoch: Epoch,
    /// Updates with seq below the snapshot are compacted away; the snapshot
    /// itself is re-encrypted under `current_epoch` at compaction time, which
    /// lets you garbage-collect stale `KeySlot`s for retired epochs.
    pub snapshot_seq: u64,
    pub members: Vec<Member>,
    // current epoch for everyone, + any recent epochs still live in the log
    pub key_slots: Vec<KeySlot>,
    /// List title, AEAD-encrypted under the current DEK. Optional.
    pub encrypted_name: Option<Vec<u8>>,
}

/// base64 (standard) for `Vec<u8>` fields via `#[serde(with = "b64")]`.
pub mod b64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

// ── Users ───────────────────────────────────────────────────────────────────

/// Step 1 of registration. The server derives `member_id` from `identity_pub`
/// and uses it as OPAQUE's `credential_identifier`; no username is needed yet.
#[derive(Debug, Clone, Deserialize)]
pub struct StartRegisterRequest {
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub registration_req: Vec<u8>,
}

/// Step 2 of registration. Carries the OPAQUE upload plus the public identity
/// the account is built around, and the user's private keys already sealed
/// under the `export_key`-derived master key (server-escrowed, opaque to us).
#[derive(Debug, Clone, Deserialize)]
pub struct FinishRegisterRequest {
    pub username: String,
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub signing_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_secret_keys: Vec<u8>,
    #[serde(with = "b64")]
    pub registration_up: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FinishRegisterResponse {
    pub member_id: Uuid,
}

/// Step 1 of login. `username` is the public lookup handle; the server maps it
/// to the stored `opaque_record` + `member_id` (the `credential_identifier`).
#[derive(Debug, Clone, Deserialize)]
pub struct LoginStartRequest {
    pub username: String,
    #[serde(with = "b64")]
    pub credential_req: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginStartResponse {
    /// Echoed back on finish so the server can recover the stashed OPAQUE state.
    pub login_id: Uuid,
    #[serde(with = "b64")]
    pub credential_response: Vec<u8>,
}

/// Step 2 of login.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginFinishRequest {
    pub login_id: Uuid,
    #[serde(with = "b64")]
    pub credential_finalization: Vec<u8>,
}

/// On success: the bearer token plus everything a fresh device needs to
/// rehydrate its keys from escrow (unwrap `wrapped_secret_keys` with the
/// `export_key`-derived master key the client just recomputed locally).
#[derive(Debug, Clone, Serialize)]
pub struct LoginFinishResponse {
    pub token: String,
    pub member_id: Uuid,
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub signing_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub wrapped_secret_keys: Vec<u8>,
}

// ── Updates ─────────────────────────────────────────────────────────────────

/// Body of `POST /lists/{list_id}/updates`. `seq` is NOT present — the server
/// assigns it. `list_id` comes from the path, not the body.
#[derive(Debug, Clone, Deserialize)]
pub struct AppendUpdate {
    pub version: u8,
    pub epoch: u32,
    pub author: Uuid,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppendResult {
    pub seq: i64,
}

/// One row returned from `GET /lists/{list_id}/updates?after=N`.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct StoredUpdateDto {
    pub seq: i64,
    pub epoch: i64,
    pub author: Uuid,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullParams {
    #[serde(default)]
    pub after: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    500
}

// ── Snapshots ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SnapshotDto {
    pub epoch: i64,
    pub covers_seq: i64,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PutSnapshot {
    pub epoch: i64,
    pub covers_seq: i64,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

// ── Lists / members / keys ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct MemberDto {
    pub member_id: Uuid,
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub signing_pub: Vec<u8>,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct KeySlotDto {
    pub epoch: i64,
    #[serde(with = "b64")]
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetadataResponse {
    pub list_id: Uuid,
    pub current_epoch: i64,
    pub snapshot: Option<SnapshotDto>,
    pub members: Vec<MemberDto>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddMemberRequest {
    pub member_id: Uuid,
    pub role: Role,
    /// The current-epoch DEK, sealed to this member's identity_pub by an owner
    /// client. The server stores it blind.
    #[serde(with = "b64")]
    pub wrapped_dek: Vec<u8>,
    pub epoch: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemoveMemberRequest {
    pub remove_member_id: Uuid,
    /// The current-epoch DEK, sealed to this member's identity_pub by an owner
    /// client. The server stores it blind.
    #[serde(with = "b64")]
    pub wrapped_dek: Vec<u8>,
    pub epoch: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserPubkeysDto {
    pub member_id: Uuid,
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub signing_pub: Vec<u8>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginDto {
    pub state: Vec<u8>,
    /// The member this login is for; `None` only on the unknown-user path.
    pub member_id: Option<Uuid>,
}

// ── Canonical signing view (must mirror the client) ─────────────────────────

/// AAD = version ‖ list_id(16) ‖ epoch_le(4) ‖ author(16) ‖ nonce(24).
pub fn aead_aad(version: u8, list_id: &Uuid, epoch: u32, author: &Uuid, nonce: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + 4 + 16 + nonce.len());
    v.push(version);
    v.extend_from_slice(list_id.as_bytes());
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(author.as_bytes());
    v.extend_from_slice(nonce);
    v
}

/// Signed view = AAD ‖ ciphertext. Ed25519 is verified over this.
pub fn signing_view(
    version: u8,
    list_id: &Uuid,
    epoch: u32,
    author: &Uuid,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut v = aead_aad(version, list_id, epoch, author, nonce);
    v.extend_from_slice(ciphertext);
    v
}
