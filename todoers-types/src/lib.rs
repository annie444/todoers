//! Wire + key schema for a zero-knowledge, shareable todo list.
//!
//! Byte fields are base64-encoded so the API is JSON-inspectable for a scaffold.
//! In production you'd likely switch the update path to `application/octet-stream`
//! carrying the client's postcard-serialized `UpdatePayload` directly.
//!
//! The `signing_view` here MUST match the client's canonical encoding exactly,
//! or server-side verification will reject valid updates.

use hmac::{Hmac, KeyInit, Mac};
use oldsha2::Sha512;
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::key_exchange::group::ristretto255::Ristretto255;
use opaque_ke::key_exchange::tripledh::TripleDh;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

pub type HmacSha256 = Hmac<Sha256>;
pub const DEK_LEN: usize = 32;

#[derive(Debug)]
pub struct SharedCipherSuite;

impl CipherSuite for SharedCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
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

/// base64 (standard) for `[u8; 16]` fields via `#[serde(with = "b6416")]`.
pub mod b6416 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let mut data = [0u8; 16];
        let decoded = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        data.copy_from_slice(&decoded);
        Ok(data)
    }
}

/// base64 (standard) for `[u8; 24]` fields via `#[serde(with = "b6424")]`.
pub mod b6424 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 24], D::Error> {
        let s = String::deserialize(d)?;
        let mut data = [0u8; 24];
        let decoded = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        data.copy_from_slice(&decoded);
        Ok(data)
    }
}

/// base64 (standard) for `[u8; 32]` fields via `#[serde(with = "b6432")]`.
pub mod b6432 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let mut data = [0u8; 32];
        let decoded = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        data.copy_from_slice(&decoded);
        Ok(data)
    }
}

/// base64 (standard) for `[u8; 64]` fields via `#[serde(with = "b6464")]`.
pub mod b6464 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let mut data = [0u8; 64];
        let decoded = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        data.copy_from_slice(&decoded);
        Ok(data)
    }
}

/// Random 16-byte list identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListId(#[serde(with = "b6416")] pub [u8; 16]);

impl From<Vec<u8>> for ListId {
    fn from(bytes: Vec<u8>) -> Self {
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        Self(id)
    }
}

/// Stable per-user id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Zeroize)]
pub struct MemberId(#[serde(with = "b6416")] pub [u8; 16]);

impl From<Vec<u8>> for MemberId {
    fn from(bytes: Vec<u8>) -> Self {
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        Self(id)
    }
}

impl MemberId {
    /// The raw 16 bytes — used directly as OPAQUE's `credential_identifier` on
    /// both the client and the server, so the two MUST agree byte-for-byte.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Derive the stable member id from the X25519 identity public key.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Zeroize)]
pub struct X25519Pub(#[serde(with = "b6432")] pub [u8; 32]);

impl From<Vec<u8>> for X25519Pub {
    fn from(bytes: Vec<u8>) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Self(id)
    }
}

/// Ed25519 public key — update signatures are verified against this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Zeroize)]
pub struct Ed25519Pub(#[serde(with = "b6432")] pub [u8; 32]);

impl From<Vec<u8>> for Ed25519Pub {
    fn from(bytes: Vec<u8>) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Self(id)
    }
}

/// DEK generation. Bumped on every membership-driven rotation. Each update
/// records the epoch it was encrypted under so readers pick the right key.
pub type Epoch = u32;

#[derive(Zeroize, Clone, PartialEq, Eq)]
#[zeroize(drop)] // Automatically zeroes out when dropped
pub struct Dek {
    inner: Box<[u8; 32]>,
}

impl From<Vec<u8>> for Dek {
    fn from(bytes: Vec<u8>) -> Self {
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Self {
            inner: Box::new(id),
        }
    }
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
    #[serde(with = "b6424")]
    pub nonce: [u8; 24],
    /// AEAD(DEK[epoch], nonce, plaintext = Loro binary update, aad = binding).
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    /// Ed25519 over `signing_view(&payload)` (encrypt-then-sign).
    #[serde(with = "b6464")]
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
    #[serde(with = "b64")]
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
    #[serde(with = "b64")]
    pub registration_req: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct StartRegisterResponse {
    #[serde(with = "b64")]
    pub response: Vec<u8>,
}

/// Step 2 of registration. Carries the OPAQUE upload plus the public identity
/// the account is built around, and the user's private keys already sealed
/// under the `export_key`-derived master key (server-escrowed, opaque to us).
#[derive(Clone, Deserialize, Serialize)]
pub struct FinishRegisterRequest {
    pub username: String,
    pub identity_pub: X25519Pub,
    #[serde(with = "b6432")]
    pub signing_pub: [u8; 32],
    #[serde(with = "b64")]
    pub wrapped_secret_keys: Vec<u8>,
    #[serde(with = "b64")]
    pub registration_up: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishRegisterResponse {
    pub member_id: Uuid,
}

/// Step 1 of login. `username` is the public lookup handle; the server maps it
/// to the stored `opaque_record` + `member_id` (the `credential_identifier`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginStartRequest {
    pub username: String,
    #[serde(with = "b64")]
    pub credential_req: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Echoed back on finish so the server can recover the stashed OPAQUE state.
    pub login_id: Uuid,
    #[serde(with = "b64")]
    pub credential_response: Vec<u8>,
}

/// Step 2 of login.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginFinishRequest {
    pub login_id: Uuid,
    #[serde(with = "b64")]
    pub credential_finalization: Vec<u8>,
}

/// On success: the bearer token plus everything a fresh device needs to
/// rehydrate its keys from escrow (unwrap `wrapped_secret_keys` with the
/// `export_key`-derived master key the client just recomputed locally).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub device_id: Uuid,
    /// Ed25519 public key the server will verify device-login challenges against.
    #[serde(with = "b6432")]
    pub device_signing_pub: [u8; 32],
    /// Human label for `GET /v1/auth/devices` (e.g. hostname). Not a secret.
    pub label: String,
}

/// One enrolled device as returned by `GET /v1/auth/devices`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceInfo {
    pub device_id: Uuid,
    pub label: String,
    /// Unix seconds when the device was enrolled.
    pub created_at: i64,
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
    pub member_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceLoginStartResponse {
    /// Echoed back on finish so the server can recover the stashed challenge.
    pub login_id: Uuid,
    /// Random nonce the client must sign with its device-auth key.
    #[serde(with = "b64")]
    pub challenge: Vec<u8>,
}

/// `POST /v1/auth/device-login/finish` — prove possession of the device-auth key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceLoginFinishRequest {
    pub login_id: Uuid,
    /// Ed25519 signature over `device_challenge_view(..)`.
    #[serde(with = "b6464")]
    pub signature: [u8; 64],
}

/// On success: a session token plus the public identity. Unlike password login
/// there is NO `wrapped_secret_keys` here — the device already recovered its keys
/// from its local encrypted cache.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceLoginFinishResponse {
    pub token: String,
    pub member_id: Uuid,
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub signing_pub: Vec<u8>,
}

// ── Updates ─────────────────────────────────────────────────────────────────

/// Body of `POST /lists/{list_id}/updates`. `seq` is NOT present — the server
/// assigns it. `list_id` comes from the path, not the body.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResult {
    pub seq: i64,
}

/// One row returned from `GET /lists/{list_id}/updates?after=N`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MemberDto {
    pub member_id: Uuid,
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub signing_pub: Vec<u8>,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct KeySlotDto {
    pub epoch: i64,
    #[serde(with = "b64")]
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataResponse {
    pub list_id: Uuid,
    pub current_epoch: i64,
    pub snapshot: Option<SnapshotDto>,
    pub members: Vec<MemberDto>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddMemberRequest {
    pub member_id: Uuid,
    pub role: Role,
    /// The current-epoch DEK, sealed to this member's identity_pub by an owner
    /// client. The server stores it blind.
    #[serde(with = "b64")]
    pub wrapped_dek: Vec<u8>,
    pub epoch: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoveMemberRequest {
    pub remove_member_id: Uuid,
    /// The current-epoch DEK, sealed to this member's identity_pub by an owner
    /// client. The server stores it blind.
    #[serde(with = "b64")]
    pub wrapped_dek: Vec<u8>,
    pub epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserPubkeysDto {
    pub member_id: Uuid,
    #[serde(with = "b64")]
    pub identity_pub: Vec<u8>,
    #[serde(with = "b64")]
    pub signing_pub: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct LoginDto {
    #[serde(with = "b64")]
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

/// Canonical signed view for a password-less device-login challenge. The device
/// signs this with its Ed25519 device-auth key; the server verifies it against the
/// enrolled trusted key. Domain-separated so a device-login signature can never be
/// confused with an update signature (`signing_view`).
///
///   view = "todoers:device-challenge:v1" ‖ version ‖ member_id(16) ‖ device_id(16) ‖ nonce
pub fn device_challenge_view(
    version: u8,
    member_id: &Uuid,
    device_id: &Uuid,
    nonce: &[u8],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"todoers:device-challenge:v1";
    let mut v = Vec::with_capacity(DOMAIN.len() + 1 + 16 + 16 + nonce.len());
    v.extend_from_slice(DOMAIN);
    v.push(version);
    v.extend_from_slice(member_id.as_bytes());
    v.extend_from_slice(device_id.as_bytes());
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
