//! Wire DTOs for the HTTP API.
//!
//! Byte fields are base64-encoded so the API is JSON-inspectable for a scaffold.
//! In production you'd likely switch the update path to `application/octet-stream`
//! carrying the client's postcard-serialized `UpdatePayload` directly.
//!
//! The `signing_view` here MUST match the client's canonical encoding exactly,
//! or server-side verification will reject valid updates.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[derive(Debug, Serialize, Deserialize, Copy, Clone, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "member_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
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
///
/// NOTE: `export_key` itself is NEVER sent — it stays on the client. Only the
/// already-wrapped `wrapped_secret_keys` blob crosses the wire.
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
