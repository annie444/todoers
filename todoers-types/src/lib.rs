//! Wire + key schema for a zero-knowledge, shareable todo list.
//!
//! Byte fields are base64-encoded so the API is JSON-inspectable for a scaffold.
//! In production you'd likely switch the update path to `application/octet-stream`
//! carrying the client's postcard-serialized `UpdatePayload` directly.
//!
//! The `signing_view` here MUST match the client's canonical encoding exactly,
//! or server-side verification will reject valid updates.

use std::{ops::Deref, str::FromStr};

use hmac::{Hmac, KeyInit, Mac};
use oldsha2::Sha512;
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::key_exchange::group::ristretto255::Ristretto255;
use opaque_ke::key_exchange::tripledh::TripleDh;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type HmacSha256 = Hmac<Sha256>;
pub const DEK_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum TypeError {
    #[error("invalid length")]
    InvalidLength,
}

macro_rules! impls {
    ($type:tt, $size:expr) => {
        impl Deref for $type {
            type Target = [u8; $size];
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl AsRef<[u8; $size]> for $type {
            fn as_ref(&self) -> &[u8; $size] {
                &self.0
            }
        }
        impl AsMut<[u8; $size]> for $type {
            fn as_mut(&mut self) -> &mut [u8; $size] {
                &mut self.0
            }
        }
        impl From<$type> for Vec<u8> {
            fn from(bytes: $type) -> Self {
                bytes.0.to_vec()
            }
        }
        impl From<[u8; $size]> for $type {
            fn from(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }
        }
        impl From<&[u8; $size]> for $type {
            fn from(bytes: &[u8; $size]) -> Self {
                Self(*bytes)
            }
        }
        impl TryFrom<Vec<u8>> for $type {
            type Error = TypeError;
            fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
                bytes
                    .try_into()
                    .map($type)
                    .map_err(|_| TypeError::InvalidLength)
            }
        }
        impl TryFrom<&[u8]> for $type {
            type Error = TypeError;
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                bytes
                    .try_into()
                    .map($type)
                    .map_err(|_| TypeError::InvalidLength)
            }
        }
        impl $type {
            pub fn new(key: [u8; $size]) -> Self {
                Self(key)
            }
            pub fn new_with_mut<F>(f: F) -> Self
            where
                F: FnOnce(&mut [u8; $size]),
            {
                let mut inner = [0u8; $size];
                f(&mut inner);
                Self(inner)
            }
            pub fn new_with<F>(f: F) -> Self
            where
                F: FnOnce() -> [u8; $size],
            {
                Self(f())
            }
            pub fn try_new_with<F, E>(f: F) -> Result<Self, E>
            where
                F: FnOnce() -> Result<[u8; $size], E>,
                E: std::error::Error + Send + Sync + 'static,
            {
                Ok(Self(f()?))
            }
            pub fn generate<Rng>(rng: &mut Rng) -> Self
            where
                Rng: old_rand_core::RngCore + old_rand_core::CryptoRng,
            {
                let mut inner = [0u8; $size];
                rng.fill_bytes(&mut inner);
                Self(inner)
            }
            pub fn as_slice(&self) -> &[u8] {
                self.as_ref()
            }
        }
        #[cfg(feature = "sqlite")]
        impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for $type
        where
            &'r [u8]: sqlx::Decode<'r, DB>,
        {
            fn decode(
                value: <DB as sqlx::Database>::ValueRef<'r>,
            ) -> Result<Self, sqlx::error::BoxDynError> {
                let bytes: &[u8] = <&[u8] as sqlx::Decode<DB>>::decode(value)?;
                if bytes.len() != $size {
                    return Err(sqlx::error::BoxDynError::from(TypeError::InvalidLength));
                }
                let mut slice = [0u8; $size];
                slice.copy_from_slice(bytes);
                Ok(Self(slice))
            }
        }
    };
}

#[derive(Debug)]
pub struct SharedCipherSuite;

impl CipherSuite for SharedCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

/// Random 16-byte list identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct ListId([u8; 16]);

impls!(ListId, 16);

/// Stable per-user id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct MemberId([u8; 16]);

impls!(MemberId, 16);

impl MemberId {
    /// Derive the stable member id from the X25519 identity public key.
    pub fn from_identity_pub(identity_pub: &X25519Pub) -> Self {
        let mut id = [0u8; 16];
        let mac = HmacSha256::new_from_slice(b"todoers:member-id:identity:v0001")
            .expect("Key is the right size for HMAC-SHA256") // 32 bytes, guaranteed by the type system
            .chain_update(identity_pub.as_ref())
            .finalize()
            .into_bytes()
            .to_vec();
        id.copy_from_slice(&mac[..16]);
        Self(id)
    }
}

/// Stable per-device id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct DeviceId([u8; 16]);

impls!(DeviceId, 16);

impl DeviceId {
    /// Derive the stable member id from the X25519 identity public key.
    pub fn from_identity_pub(identity_pub: &X25519Pub) -> Self {
        let mut id = [0u8; 16];
        let mac = HmacSha256::new_from_slice(b"todoers:device-id:identity:v0001")
            .expect("Key is the right size for HMAC-SHA256") // 32 bytes, guaranteed by the type system
            .chain_update(identity_pub.as_ref())
            .finalize()
            .into_bytes()
            .to_vec();
        id.copy_from_slice(&mac[..16]);
        Self(id)
    }
}

/// X25519 public key — DEKs are sealed *to* this.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct X25519Secret([u8; 32]);

impl From<x25519_dalek::StaticSecret> for X25519Secret {
    fn from(sk: x25519_dalek::StaticSecret) -> Self {
        Self(sk.to_bytes())
    }
}

impls!(X25519Secret, 32);

/// X25519 public key — DEKs are sealed *to* this.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct X25519Pub([u8; 32]);

impl From<x25519_dalek::PublicKey> for X25519Pub {
    fn from(pk: x25519_dalek::PublicKey) -> Self {
        Self(pk.to_bytes())
    }
}

impl From<X25519Pub> for x25519_dalek::PublicKey {
    fn from(pk: X25519Pub) -> Self {
        Self::from(pk.0)
    }
}

impl From<&X25519Pub> for x25519_dalek::PublicKey {
    fn from(pk: &X25519Pub) -> Self {
        Self::from(pk.0)
    }
}

impls!(X25519Pub, 32);

/// Ed25519 signing key — update signatures are verified against this.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct Ed25519Signing([u8; 32]);

impls!(Ed25519Signing, 32);

impl From<ed25519_dalek::SigningKey> for Ed25519Signing {
    fn from(sk: ed25519_dalek::SigningKey) -> Self {
        Self(sk.to_bytes())
    }
}

impl From<Ed25519Signing> for ed25519_dalek::SigningKey {
    fn from(sk: Ed25519Signing) -> Self {
        Self::from_bytes(&sk.0)
    }
}

impl From<&Ed25519Signing> for ed25519_dalek::SigningKey {
    fn from(sk: &Ed25519Signing) -> Self {
        Self::from_bytes(&sk.0)
    }
}

/// Ed25519 public key — update signatures are verified against this.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct Ed25519Pub([u8; 32]);

impls!(Ed25519Pub, 32);

impl From<ed25519_dalek::VerifyingKey> for Ed25519Pub {
    fn from(pk: ed25519_dalek::VerifyingKey) -> Self {
        Self(pk.to_bytes())
    }
}

impl TryFrom<Ed25519Pub> for ed25519_dalek::VerifyingKey {
    type Error = ed25519_dalek::SignatureError;
    fn try_from(pk: Ed25519Pub) -> Result<Self, Self::Error> {
        Self::from_bytes(&pk.0)
    }
}

impl TryFrom<&Ed25519Pub> for ed25519_dalek::VerifyingKey {
    type Error = ed25519_dalek::SignatureError;
    fn try_from(pk: &Ed25519Pub) -> Result<Self, Self::Error> {
        Self::from_bytes(&pk.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct Signature(#[serde(with = "serde_arrays")] [u8; ed25519_dalek::Signature::BYTE_SIZE]);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        Self(sig.to_bytes())
    }
}

impls!(Signature, 64);

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct Nonce([u8; 24]);

impls!(Nonce, 24);

/// DEK generation. Bumped on every membership-driven rotation. Each update
/// records the epoch it was encrypted under so readers pick the right key.
pub type Epoch = i64;

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop,
)]
#[cfg_attr(
    all(feature = "postgres", not(feature = "sqlite")),
    derive(sqlx::Type),
    sqlx(transparent)
)]
pub struct Dek([u8; DEK_LEN]);

impls!(Dek, DEK_LEN);

// ---------------------------------------------------------------------------
// Update envelope — the unit the server stores and relays.
// ---------------------------------------------------------------------------

/// What the author actually produces and signs. `seq` is deliberately NOT in
/// here: the server assigns storage order on append, and CRDT merge is
/// order-independent, so the author never needs to know its slot in advance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize)]
pub struct UpdatePayload {
    pub version: u8,
    pub list_id: ListId,
    pub epoch: Epoch,
    pub author: MemberId,
    /// Per-update random XChaCha20-Poly1305 nonce.
    pub nonce: Nonce,
    /// AEAD(DEK[epoch], nonce, plaintext = Loro binary update, aad = binding).
    pub ciphertext: Vec<u8>,
    /// Ed25519 over `signing_view(&payload)` (encrypt-then-sign).
    pub signature: Signature,
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

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "member_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
}

impl From<String> for Role {
    fn from(s: String) -> Self {
        match s.as_str() {
            "owner" => Role::Owner,
            _ => Role::Member,
        }
    }
}

impl FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Role::Owner),
            _ => Ok(Role::Member),
        }
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

// ── Users ───────────────────────────────────────────────────────────────────

/// Step 1 of registration. The server derives `member_id` from `identity_pub`
/// and uses it as OPAQUE's `credential_identifier`; no username is needed yet.
#[derive(Clone, Deserialize, Serialize)]
pub struct StartRegisterRequest {
    pub identity_pub: X25519Pub,
    pub registration_req: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StartRegisterResponse {
    pub response: Vec<u8>,
}

/// Step 2 of registration. Carries the OPAQUE upload plus the public identity
/// the account is built around, and the user's private keys already sealed
/// under the `export_key`-derived master key (server-escrowed, opaque to us).
#[derive(Clone, Deserialize, Serialize)]
pub struct FinishRegisterRequest {
    pub username: String,
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
    pub wrapped_secret_keys: Vec<u8>,
    pub registration_up: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishRegisterResponse {
    pub member_id: MemberId,
}

/// Step 1 of login. `username` is the public lookup handle; the server maps it
/// to the stored `opaque_record` + `member_id` (the `credential_identifier`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginStartRequest {
    pub username: String,
    pub credential_req: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Echoed back on finish so the server can recover the stashed OPAQUE state.
    pub login_id: Uuid,
    pub credential_response: Vec<u8>,
}

/// Step 2 of login.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginFinishRequest {
    pub login_id: Uuid,
    pub credential_finalization: Vec<u8>,
}

/// On success: the bearer token plus everything a fresh device needs to
/// rehydrate its keys from escrow (unwrap `wrapped_secret_keys` with the
/// `export_key`-derived master key the client just recomputed locally).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    pub token: String,
    pub member_id: MemberId,
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
    pub wrapped_secret_keys: Vec<u8>,
}

// ── Trusted device keys (password-less device unlock) ────────────────────────
// A device stores its unlocked keys encrypted on disk under a local AGE/SSH key
// (password-less unlock). Inside that encrypted cache it also keeps a dedicated
// Ed25519 *device-auth* keypair; the public half is enrolled with the server as
// a "trusted key". To sync without a password the device does a challenge/response
// "device login": the server hands it a random nonce, it signs
// `device_challenge_view(..)` with the device-auth key, and the server verifies
// against the enrolled public key. Revoking a device removes its trusted key, so
// the server then rejects that device even if its on-disk cache was stolen.

/// Domain-separated version tag for the device-auth challenge signature. Bumped
/// only if the signed byte layout changes; client and server MUST agree.
pub const DEVICE_CHALLENGE_VERSION: u8 = 1;

/// `POST /v1/auth/devices` — enroll this device's trusted (Ed25519) public key.
/// Authenticated with an ordinary session (a password login, typically).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrollDeviceRequest {
    /// Client-generated 16-byte device identifier (opaque to the server).
    pub device_id: DeviceId,
    /// Ed25519 public key the server will verify device-login challenges against.
    pub device_signing_pub: Ed25519Pub,
    /// Human label for `GET /v1/auth/devices` (e.g. hostname). Not a secret.
    pub label: String,
}

/// One enrolled device as returned by `GET /v1/auth/devices`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceInfo {
    pub device_id: DeviceId,
    pub label: String,
    /// Unix seconds when the device was enrolled.
    pub created_at: OffsetDateTime,
    /// True once the device has been revoked (its trusted key no longer authenticates).
    pub revoked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<DeviceInfo>,
}

/// `POST /v1/auth/device-login/start` — begin a password-less device login.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceLoginStartRequest {
    pub member_id: MemberId,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceLoginStartResponse {
    /// Echoed back on finish so the server can recover the stashed challenge.
    pub login_id: Uuid,
    /// Random nonce the client must sign with its device-auth key.
    pub challenge: Nonce,
}

/// `POST /v1/auth/device-login/finish` — prove possession of the device-auth key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceLoginFinishRequest {
    pub login_id: Uuid,
    /// Ed25519 signature over `device_challenge_view(..)`.
    pub signature: Signature,
}

/// On success: a session token plus the public identity. Unlike password login
/// there is NO `wrapped_secret_keys` here — the device already recovered its keys
/// from its local encrypted cache.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceLoginFinishResponse {
    pub token: String,
    pub member_id: MemberId,
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
}

// ── Updates ─────────────────────────────────────────────────────────────────

/// Body of `POST /v1/lists/updates`. `seq` is NOT present — the server assigns
/// it. `list_id` is carried in the body (paths are id-free).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppendUpdate {
    pub list_id: ListId,
    pub version: u8,
    pub epoch: Epoch,
    pub author: MemberId,
    pub nonce: Nonce,
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResult {
    pub seq: i64,
}

/// One row returned from `GET /lists/{list_id}/updates?after=N`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StoredUpdateDto {
    pub seq: i64,
    pub epoch: Epoch,
    pub author: MemberId,
    pub nonce: Nonce,
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
}

/// Body of `PUT /v1/lists/updates` — pull updates for `list_id` after `after`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PullParams {
    pub list_id: ListId,
    #[serde(default)]
    pub after: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    500
}

// ── Snapshots ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SnapshotDto {
    pub epoch: Epoch,
    pub covers_seq: i64,
    pub nonce: Nonce,
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
}

/// Body of `POST /v1/lists/snapshot` — `list_id` is carried in the body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PutSnapshot {
    pub list_id: ListId,
    pub epoch: Epoch,
    pub covers_seq: i64,
    pub nonce: Nonce,
    pub ciphertext: Vec<u8>,
    pub signature: Signature,
}

// ── Lists / members / keys ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateListRequest {
    /// Client-chosen list id (opaque 16 bytes). The client mints it so a list
    /// created offline keeps a stable id and can be uploaded idempotently later;
    /// the server adopts it rather than assigning its own.
    pub list_id: ListId,
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MemberDto {
    pub member_id: MemberId,
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct KeySlotDto {
    pub epoch: Epoch,
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataResponse {
    pub list_id: ListId,
    pub current_epoch: Epoch,
    pub snapshot: Option<SnapshotDto>,
    pub members: Vec<MemberDto>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddMemberRequest {
    pub list_id: ListId,
    pub member_id: MemberId,
    pub role: Role,
    /// The current-epoch DEK, sealed to this member's identity_pub by an owner
    /// client. The server stores it blind.
    pub wrapped_dek: Vec<u8>,
    pub epoch: Epoch,
}

/// One remaining member's copy of the post-rotation DEK, sealed to *their own*
/// identity_pub. A removal ships one of these per surviving member so each can
/// open the new epoch's DEK (a single blob can only be opened by its recipient).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeySlotEntry {
    pub member_id: MemberId,
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoveMemberRequest {
    pub list_id: ListId,
    pub remove_member_id: MemberId,
    /// The pre-rotation epoch the client read; the server rotates to `epoch + 1`.
    pub epoch: Epoch,
    /// The fresh DEK sealed individually to each *remaining* member. The server
    /// stores them blind under the new epoch and drops the removed member's slots.
    pub new_slots: Vec<KeySlotEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserPubkeysDto {
    pub member_id: MemberId,
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
}

#[derive(Debug, Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct LoginDto {
    pub state: Vec<u8>,
    /// The member this login is for; `None` only on the unknown-user path.
    pub member_id: Option<MemberId>,
}

// ── Canonical signing view (must mirror the client) ─────────────────────────

/// AAD = version ‖ list_id(16) ‖ epoch_le(4) ‖ author(16) ‖ nonce(24).
pub fn aead_aad(
    version: u8,
    list_id: &ListId,
    epoch: Epoch,
    author: &MemberId,
    nonce: &Nonce,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 16 + 4 + 16 + nonce.len());
    v.push(version);
    v.extend_from_slice(list_id.as_ref());
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(author.as_ref());
    v.extend_from_slice(nonce.as_ref());
    v
}

/// Canonical signed view for a password-less device-login challenge. The device
/// signs this with its Ed25519 device-auth key; the server verifies it against the
/// enrolled trusted key. Domain-separated so a device-login signature can never be
/// confused with an update signature (`signing_view`).
///
///   view = "todoers:device-challenge:v1" ‖ version ‖ member_id(16) ‖ device_id(16) ‖ nonce
pub fn device_challenge_view(
    version: u8,
    member_id: &MemberId,
    device_id: &DeviceId,
    nonce: &Nonce,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"todoers:device-challenge:v1";
    let mut v = Vec::with_capacity(DOMAIN.len() + 1 + 16 + 16 + nonce.len());
    v.extend_from_slice(DOMAIN);
    v.push(version);
    v.extend_from_slice(member_id.as_ref());
    v.extend_from_slice(device_id.as_ref());
    v.extend_from_slice(nonce.as_ref());
    v
}

/// Signed view = AAD ‖ ciphertext. Ed25519 is verified over this.
pub fn signing_view(
    version: u8,
    list_id: &ListId,
    epoch: Epoch,
    author: &MemberId,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut v = aead_aad(version, list_id, epoch, author, nonce);
    v.extend_from_slice(ciphertext);
    v
}
