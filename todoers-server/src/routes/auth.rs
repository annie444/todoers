//! Authentication edge — OPAQUE registration & login over a stateless HTTP API.
//!
//! OPAQUE (opaque-ke) lets the client prove knowledge of a password without ever
//! revealing it to the server. Two flows, each two messages:
//!
//!   register: start (server is stateless) → finish (persist the password file)
//!   login:    start (server stashes transient state) → finish (mint a session)
//!
//! The server is a blind relay: it stores the OPAQUE `opaque_record`, the user's
//! public identity, and the user's *already-sealed* private keys, and never sees
//! the password or the `export_key`.

use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{KeyInit, Mac};
use old_rand_core::{OsRng, RngCore};
use opaque_ke::ServerLoginParameters;
use sha2::{Digest, Sha512};
use time::{Duration, OffsetDateTime};
use tracing::error;
use uuid::Uuid;

use todoers_types::{HmacSha256, MemberId, X25519Pub};

use crate::crypto::{
    CredentialReq, Finalization, Login, PasswordFile, Registration, RegistrationReq, RegistrationUp,
};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::wire::{
    FinishRegisterRequest, FinishRegisterResponse, LoginFinishRequest, LoginFinishResponse,
    LoginStartRequest, LoginStartResponse, StartRegisterRequest,
};

/// How long a freshly minted session token stays valid.
const SESSION_TTL: Duration = Duration::days(30);

/// The authenticated caller, resolved from a session token on every request.
#[derive(Debug, Clone, Copy)]
pub struct AuthMember(pub Uuid);

impl FromRequestParts<AppState> for AuthMember {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let token = header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?
            .trim();

        // Look the token up by its hash; expiry is enforced in the query.
        let token_hash = hash_token(token)?;
        let member_id = state
            .db
            .lookup_session(&token_hash)
            .await?
            .ok_or(AppError::Unauthorized)?;
        Ok(AuthMember(member_id))
    }
}

// ── Registration ─────────────────────────────────────────────────────────────
// Two round-trips; the server holds NO state between them. `member_id` is always
// derived from `identity_pub` (never trusted as a raw value), and it doubles as
// OPAQUE's `credential_identifier` so login can reproduce it from the stored row.

/// Step 1: respond to a RegistrationRequest. Returns the RegistrationResponse
/// bytes for the client to feed into `ClientRegistration::finish`.
pub async fn registration_start(
    State(state): State<AppState>,
    Json(req): Json<StartRegisterRequest>,
) -> AppResult<Vec<u8>> {
    let identity_pub = parse_x25519(&req.identity_pub)?;
    let member_id = MemberId::from_identity_pub(&identity_pub);

    let registration_req = RegistrationReq::deserialize(&req.registration_req)?;
    let result = Registration::start(state.opaque.get(), registration_req, member_id.as_bytes())?;
    Ok(result.message.serialize().to_vec())
}

/// Step 2: store the client's RegistrationUpload as the user's password file,
/// alongside the public identity and escrowed (already-sealed) private keys.
pub async fn registration_finish(
    State(state): State<AppState>,
    Json(req): Json<FinishRegisterRequest>,
) -> AppResult<Json<FinishRegisterResponse>> {
    let identity_pub = parse_x25519(&req.identity_pub)?;
    if req.signing_pub.len() != 32 {
        return Err(AppError::BadRequest("signing_pub must be 32 bytes".into()));
    }

    // Re-derive the id from the uploaded key so a client can't forge a mismatch.
    let member_id = MemberId::from_identity_pub(&identity_pub);
    let member_uuid = Uuid::from_bytes(member_id.0);

    let upload = RegistrationUp::deserialize(&req.registration_up)?;
    let opaque_record = Registration::finish(upload).serialize().to_vec();

    state
        .db
        .create_user(
            member_uuid,
            &req.username,
            &req.identity_pub,
            &req.signing_pub,
            &req.wrapped_secret_keys,
            &opaque_record,
        )
        .await?;

    Ok(Json(FinishRegisterResponse {
        member_id: member_uuid,
    }))
}

// ── Login ────────────────────────────────────────────────────────────────────
// The server holds transient state between the two messages: `ServerLogin::start`
// emits a CredentialResponse (to the client) AND a ServerLogin value that finish
// needs. We stash the latter in `login_cache`, keyed by a `login_id`.

/// Step 1: look the user up by username, run `ServerLogin::start`, stash the
/// resulting state, and return `(login_id, credential_response)`.
pub async fn login_start(
    State(state): State<AppState>,
    Json(req): Json<LoginStartRequest>,
) -> AppResult<Json<LoginStartResponse>> {
    let mut rng = OsRng;
    let credential_req = CredentialReq::deserialize(&req.credential_req)?;

    let user = state.db.fetch_login_user(&req.username).await?;

    // `credential_identifier` MUST match what registration used. For a real user
    // that's the stored member_id; for an unknown user we pass `None` with a
    // deterministic placeholder so the response is enumeration-resistant. The
    // placeholder path can never finish successfully.
    let (password_file, member_id): (Option<PasswordFile>, Option<Uuid>) = match &user {
        Some(u) => (
            Some(PasswordFile::deserialize(&u.opaque_record)?),
            Some(u.member_id),
        ),
        None => (None, None),
    };
    let credential_identifier = match member_id {
        Some(id) => *id.as_bytes(),
        None => placeholder_credential_id(&state, &req.username),
    };

    let result = Login::start(
        &mut rng,
        state.opaque.get(),
        password_file,
        credential_req,
        &credential_identifier,
        ServerLoginParameters::default(),
    )
    .map_err(|e| {
        error!(error = ?e, "login start failed");
        AppError::Unauthorized
    })?;

    let state_bytes = result.state.serialize().to_vec();
    let login_id = state.db.login_start(&state_bytes, member_id).await?;

    Ok(Json(LoginStartResponse {
        login_id,
        credential_response: result.message.serialize().to_vec(),
    }))
}

/// Step 2: recover the stashed state, finish the AKE (proof the client knew the
/// password), mint a session token, and return it with the escrow blob so a
/// fresh device can rehydrate its keys.
pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> AppResult<Json<LoginFinishResponse>> {
    let stash = state
        .db
        .login_finish(req.login_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    // Only the unknown-user path leaves this NULL, and that path can't reach a
    // successful finish — but guard anyway.
    let member_id = stash.member_id.ok_or(AppError::Unauthorized)?;

    let login_state = Login::deserialize(&stash.state)?;
    let finalization = Finalization::deserialize(&req.credential_finalization)?;
    let result = login_state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|e| {
            error!(error = ?e, "login finish failed");
            AppError::Unauthorized
        })?;
    // Proof of password knowledge. We bind our own token to the member rather
    // than handing the raw session key back as a credential.
    let _session_key = result.session_key;

    let keys = state
        .db
        .fetch_user_keys(member_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let (token, token_hash) = mint_session_token();
    let expires_at = OffsetDateTime::now_utc() + SESSION_TTL;
    state
        .db
        .create_session(member_id, &token_hash, expires_at)
        .await?;

    Ok(Json(LoginFinishResponse {
        token,
        member_id,
        identity_pub: keys.identity_pub,
        signing_pub: keys.signing_pub,
        wrapped_secret_keys: keys.wrapped_secret_keys,
    }))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn parse_x25519(bytes: &[u8]) -> AppResult<X25519Pub> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::BadRequest("identity_pub must be 32 bytes".into()))?;
    Ok(X25519Pub(arr))
}

/// Mint a fresh bearer token and the hash to persist for it. Returns
/// `(token, token_hash)`: the `token` is sent to the client exactly once; only
/// the `token_hash` is ever stored, so a leak of the `sessions` table can't be
/// replayed as a credential.
///
/// LEARNING SPOT #2 — write the body:
///   1. Draw >=16 bytes of cryptographic randomness (`rand_core::OsRng`).
///   2. Encode them into the bearer string the client sends back (base64/hex).
///   3. Hash the token (e.g. SHA-256 via the `sha2` crate) → `token_hash`.
///
/// Whatever hash you pick here MUST match `hash_token` below.
fn mint_session_token() -> (String, Vec<u8>) {
    let mut token_bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut token_bytes);
    let token = STANDARD.encode(token_bytes);
    let token_hash = Sha512::digest(token_bytes).to_vec();
    (token, token_hash)
}

/// Hash a presented bearer token so the extractor can look it up by `token_hash`.
/// MUST hash identically to step 3 of `mint_session_token`.
///
/// LEARNING SPOT #2 (cont.).
fn hash_token(token: &str) -> AppResult<Vec<u8>> {
    let token_bytes = STANDARD.decode(token)?;
    Ok(Sha512::digest(token_bytes).to_vec())
}

/// Derive a stable, non-enumerable 16-byte `credential_identifier` for an unknown
/// username, so `login/start` for a missing user is indistinguishable from a real
/// one. Must be deterministic (same username → same bytes) and must NOT reveal
/// whether the user exists.
///
/// LEARNING SPOT #3 — write the body. A keyed hash works well: HMAC/keyed-BLAKE2
/// of `username` under a server-held secret. The OPAQUE setup is a convenient
/// secret source — `state.opaque.serialize()` returns stable server-only bytes
/// you can use as (or derive) the key.
fn placeholder_credential_id(state: &AppState, username: &str) -> [u8; 16] {
    let key = state.opaque.serialize();
    let mut username_id = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut username_id);
    let mac = HmacSha256::new_from_slice(&key)
        .expect("HMAC can take key of any size")
        .chain_update(username.as_bytes())
        .finalize()
        .into_bytes();
    username_id.copy_from_slice(&mac[..16]);
    username_id
}
