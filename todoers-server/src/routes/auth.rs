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

use axum::body::Bytes;
use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{KeyInit, Mac};
use old_rand_core::{OsRng, RngCore};
use opaque_ke::{CredentialRequest, ServerLoginParameters};
use sha2::{Digest, Sha512};
use time::{Duration, OffsetDateTime};
use tracing::error;

use todoers_types::{
    DeviceId, FinishRegisterRequest, FinishRegisterResponse, HmacSha256, LoginFinishRequest,
    LoginFinishResponse, LoginStartRequest, LoginStartResponse, MemberId, SharedCipherSuite,
    StartRegisterRequest, StartRegisterResponse,
};

use crate::crypto::{
    CredentialReq, Finalization, Login, PasswordFile, Registration, RegistrationReq, RegistrationUp,
};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// How long a freshly minted session token stays valid. Shared with the
/// password-less device-login path (`routes::device`).
pub(crate) const SESSION_TTL: Duration = Duration::days(30);

/// How recently a PASSWORD login must have happened for a step-up-gated
/// operation (enroll/revoke trusted device keys) to be allowed.
pub(crate) const STEP_UP_TTL: Duration = Duration::minutes(5);

/// The authenticated caller, resolved from a session token on every request.
#[derive(Debug, Clone)]
pub struct AuthMember {
    pub member_id: MemberId,
    /// Hash of the bearer token this request authenticated with. Lets handlers
    /// like logout revoke exactly this session (this device), not all of them.
    pub token_hash: [u8; 64],
    /// Device that minted this session: `None` for a password login, `Some(..)`
    /// for a password-less device login.
    pub device_id: Option<DeviceId>,
    /// When this session was created — used together with `device_id` for step-up.
    pub created_at: OffsetDateTime,
}

impl AuthMember {
    /// Require a recent PASSWORD (non-device) login for sensitive operations like
    /// enrolling or revoking trusted device keys. A device-minted session can
    /// never perform these (so a compromised device can't escalate by enrolling
    /// more devices or revoking the owner's), and a stale password session must
    /// re-authenticate.
    pub(crate) fn require_password_step_up(&self) -> AppResult<()> {
        if self.device_id.is_some() {
            return Err(AppError::StepUpRequired);
        }
        if OffsetDateTime::now_utc() - self.created_at > STEP_UP_TTL {
            return Err(AppError::StepUpRequired);
        }
        Ok(())
    }
}

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
        let session = state
            .db
            .lookup_session(&token_hash)
            .await?
            .ok_or(AppError::Unauthorized)?;
        Ok(AuthMember {
            member_id: session.member_id,
            token_hash,
            device_id: session.device_id,
            created_at: session.created_at,
        })
    }
}

// ── Registration ─────────────────────────────────────────────────────────────
// Two round-trips; the server holds NO state between them. `member_id` is always
// derived from `identity_pub` (never trusted as a raw value), and it doubles as
// OPAQUE's `credential_identifier` so login can reproduce it from the stored row.

/// `POST /v1/auth/register/start`
/// Step 1: respond to a RegistrationRequest. Returns the RegistrationResponse
/// bytes for the client to feed into `ClientRegistration::finish`.
pub async fn registration_start(State(state): State<AppState>, bytes: Bytes) -> AppResult<Bytes> {
    let req: StartRegisterRequest = postcard::from_bytes(&bytes)?;
    let member_id = MemberId::from_identity_pub(&req.identity_pub);

    let registration_req =
        RegistrationReq::deserialize(&req.registration_req).inspect_err(|e| {
            error!(error = ?e, "failed to deserialize registration request");
        })?;
    let result = Registration::start(state.opaque.get(), registration_req, member_id.as_ref())
        .map_err(|e| {
            error!(error = ?e, "registration start failed");
            AppError::BadRequest("invalid registration request".into())
        })?;
    Ok(Bytes::from(postcard::to_stdvec(&StartRegisterResponse {
        response: result.message.serialize().to_vec(),
    })?))
}

/// `POST /v1/auth/register/finish`
/// Step 2: store the client's RegistrationUpload as the user's password file,
/// alongside the public identity and escrowed (already-sealed) private keys.
pub async fn registration_finish(State(state): State<AppState>, bytes: Bytes) -> AppResult<Bytes> {
    let req: FinishRegisterRequest = postcard::from_bytes(&bytes)?;
    if req.signing_pub.len() != 32 {
        return Err(AppError::BadRequest("signing_pub must be 32 bytes".into()));
    }

    // Re-derive the id from the uploaded key so a client can't forge a mismatch.
    let member_id = MemberId::from_identity_pub(&req.identity_pub);

    let upload = RegistrationUp::deserialize(&req.registration_up).inspect_err(|e| {
        error!(error = ?e, "failed to deserialize registration upload");
    })?;
    let opaque_record = Registration::finish(upload).serialize().to_vec();

    state
        .db
        .create_user(
            &member_id,
            &req.username,
            &req.identity_pub,
            &req.signing_pub,
            &req.wrapped_secret_keys,
            &opaque_record,
        )
        .await
        .inspect_err(|e| {
            error!(error = ?e, "failed to create user in database");
        })?;

    Ok(Bytes::from(postcard::to_stdvec(&FinishRegisterResponse {
        member_id,
    })?))
}

// ── Login ────────────────────────────────────────────────────────────────────
// The server holds transient state between the two messages: `ServerLogin::start`
// emits a CredentialResponse (to the client) AND a ServerLogin value that finish
// needs. We stash the latter in `login_cache`, keyed by a `login_id`.

/// Step 1: look the user up by username, run `ServerLogin::start`, stash the
/// resulting state, and return `(login_id, credential_response)`.
pub async fn login_start(State(state): State<AppState>, bytes: Bytes) -> AppResult<Bytes> {
    let req: LoginStartRequest = postcard::from_bytes(&bytes)?;
    let credential_req: CredentialRequest<SharedCipherSuite> =
        CredentialReq::deserialize(&req.credential_req).inspect_err(|e| {
            error!(error = ?e, "failed to deserialize credential request");
        })?;

    let user = state.db.fetch_login_user(&req.username).await?;

    // `credential_identifier` MUST match what registration used. For a real user
    // that's the stored member_id; for an unknown user we pass `None` with a
    // deterministic placeholder so the response is enumeration-resistant. The
    // placeholder path can never finish successfully.
    let (password_file, member_id): (Option<PasswordFile>, Option<MemberId>) = match &user {
        Some(u) => (
            Some(PasswordFile::deserialize(&u.opaque_record)?),
            Some(u.member_id),
        ),
        None => (None, None),
    };
    let credential_identifier = match member_id {
        Some(ref id) => *id,
        None => placeholder_credential_id(&state, &req.username),
    };

    let mut rng = OsRng;
    let result = Login::start(
        &mut rng,
        state.opaque.get(),
        password_file,
        credential_req,
        credential_identifier.as_ref(),
        ServerLoginParameters::default(),
    )
    .map_err(|e| {
        error!(error = ?e, "login start failed");
        AppError::Unauthorized
    })?;

    let state_bytes = result.state.serialize().to_vec();
    let login_id = state.db.login_start(&state_bytes, member_id).await?;

    Ok(Bytes::from(postcard::to_stdvec(&LoginStartResponse {
        login_id,
        credential_response: result.message.serialize().to_vec(),
    })?))
}

/// Step 2: recover the stashed state, finish the AKE (proof the client knew the
/// password), mint a session token, and return it with the escrow blob so a
/// fresh device can rehydrate its keys.
pub async fn login_finish(State(state): State<AppState>, bytes: Bytes) -> AppResult<Bytes> {
    let req: LoginFinishRequest = postcard::from_bytes(&bytes)?;
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
        .fetch_user_keys(&member_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let (token, token_hash) = mint_session_token();
    let expires_at = OffsetDateTime::now_utc() + SESSION_TTL;
    // Password login → no device tag (this is what step-up auth requires).
    state
        .db
        .create_session(&member_id, &token_hash, expires_at, None)
        .await?;

    Ok(Bytes::from(postcard::to_stdvec(&LoginFinishResponse {
        token,
        member_id,
        identity_pub: keys.identity_pub,
        signing_pub: keys.signing_pub,
        wrapped_secret_keys: keys.wrapped_secret_keys,
    })?))
}

// ── Logout ──────────────────────────────────────────────────────────────────

pub async fn logout(State(state): State<AppState>, auth: AuthMember) -> AppResult<()> {
    state.db.delete_session(&auth.token_hash).await?;
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Mint a fresh bearer token and the hash to persist for it. Returns
/// `(token, token_hash)`: the `token` is sent to the client exactly once; only
/// the `token_hash` is ever stored, so a leak of the `sessions` table can't be
/// replayed as a credential.
pub(crate) fn mint_session_token() -> (String, [u8; 64]) {
    let mut token_bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut token_bytes);
    let token = STANDARD.encode(token_bytes);
    let token_hash: [u8; 64] = Sha512::digest(token_bytes).into();
    (token, token_hash)
}

/// Hash a presented bearer token so the extractor can look it up by `token_hash`.
/// MUST hash identically to step 3 of `mint_session_token`.
fn hash_token(token: &str) -> AppResult<[u8; 64]> {
    let token_bytes = STANDARD.decode(token)?;
    Ok(Sha512::digest(token_bytes).into())
}

/// Derive a stable, non-enumerable 16-byte `credential_identifier` for an unknown
/// username, so `login/start` for a missing user is indistinguishable from a real
/// one. Must be deterministic (same username -> same bytes) and must NOT reveal
/// whether the user exists.
fn placeholder_credential_id(state: &AppState, username: &str) -> MemberId {
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
    MemberId::new(username_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    use todoers_types::{Ed25519Pub, X25519Pub};

    #[sqlx::test]
    async fn test_placeholder_credential_id(db: sqlx::PgPool) {
        let state = AppState::new_for_test(db);
        let id1 = placeholder_credential_id(&state, "alice");
        let id2 = placeholder_credential_id(&state, "bob");
        let id3 = placeholder_credential_id(&state, "alice");
        assert_eq!(id1, id3);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_token_hashing() {
        let (token, token_hash) = mint_session_token();
        let computed_hash = hash_token(&token).expect("hashing minted token should succeed");
        assert_eq!(token_hash, computed_hash);
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_registration_flow(db: sqlx::PgPool) {
        let state = AppState::new_for_test(db);
        let app = TestServer::new(crate::routes::build_router(state).await);
        let passwd = b"test-password";

        let mut rng = OsRng;

        let client_secret = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let client_public = x25519_dalek::PublicKey::from(&client_secret);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);

        let client_registration_start = opaque_ke::ClientRegistration::<
            todoers_types::SharedCipherSuite,
        >::start(&mut rng, passwd)
        .unwrap();

        let response = app
            .post("/v1/auth/register/start")
            .bytes(
                postcard::to_stdvec(&StartRegisterRequest {
                    identity_pub: X25519Pub::new(client_public.to_bytes()),
                    registration_req: client_registration_start.message.serialize().to_vec(), // This would be a real OPAQUE request in a full test
                })
                .unwrap()
                .into(),
            )
            .await;

        response.assert_status_ok();

        let data: StartRegisterResponse = postcard::from_bytes(response.as_bytes()).unwrap();
        assert!(!data.response.is_empty());

        let response =
            opaque_ke::RegistrationResponse::<todoers_types::SharedCipherSuite>::deserialize(
                &data.response,
            )
            .unwrap();
        let client_registration_finish = client_registration_start
            .state
            .finish(&mut rng, passwd, response, Default::default())
            .unwrap();

        let response = app
            .post("/v1/auth/register/finish")
            .bytes(
                postcard::to_stdvec(&FinishRegisterRequest {
                    username: "testuser".to_string(),
                    identity_pub: X25519Pub::new(client_public.to_bytes()),
                    signing_pub: Ed25519Pub::new(*signing_key.verifying_key().as_bytes()),
                    wrapped_secret_keys: vec![], // In a real test, this would be the client's encrypted
                    // private keys, but the server doesn't actually use them in this flow, so we can
                    // leave it empty.
                    registration_up: client_registration_finish.message.serialize().to_vec(),
                })
                .unwrap()
                .into(),
            )
            .await;

        response.assert_status_ok();
        let finish: FinishRegisterResponse = postcard::from_bytes(response.as_bytes()).unwrap();
        assert_eq!(finish.member_id.as_ref().len(), 16);
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_login_round_trip(db: sqlx::PgPool) {
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        let token =
            crate::routes::testutil::register_and_login(&server, "alice", "pw-correct-horse").await;
        assert!(!token.is_empty());
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_authed_request_and_logout(db: sqlx::PgPool) {
        use axum::http::StatusCode;
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        let token = crate::routes::testutil::register_and_login(&server, "bob", "hunter2").await;

        // A valid token authenticates.
        let resp = server
            .post("/v1/auth/logout")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .await;
        resp.assert_status_ok();

        // After logout the same token is rejected.
        let resp = server
            .post("/v1/auth/logout")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_logout_is_per_device(db: sqlx::PgPool) {
        use axum::http::StatusCode;
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);

        // Two sessions of the SAME user (two devices).
        let token_a = crate::routes::testutil::register_and_login(&server, "dave", "pw").await;
        let token_b = crate::routes::testutil::login(&server, "dave", "pw")
            .await
            .token;

        // Log out device A only.
        server
            .post("/v1/auth/logout")
            .add_header(AUTHORIZATION, format!("Bearer {token_a}"))
            .await
            .assert_status_ok();

        // A is revoked…
        let resp = server
            .post("/v1/auth/logout")
            .add_header(AUTHORIZATION, format!("Bearer {token_a}"))
            .await;
        resp.assert_status(StatusCode::UNAUTHORIZED);

        // …but B is still valid.
        server
            .post("/v1/auth/logout")
            .add_header(AUTHORIZATION, format!("Bearer {token_b}"))
            .await
            .assert_status_ok();
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_bogus_token_rejected(db: sqlx::PgPool) {
        use axum::http::StatusCode;
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        // Valid base64 (so it reaches the session lookup) but no matching session.
        let bogus = STANDARD.encode([0u8; 32]);
        let resp = server
            .post("/v1/auth/logout")
            .add_header(AUTHORIZATION, format!("Bearer {bogus}"))
            .await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_login_unknown_user_is_enumeration_resistant(db: sqlx::PgPool) {
        use todoers_types::{LoginStartRequest, LoginStartResponse, SharedCipherSuite};
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);

        let login =
            opaque_ke::ClientLogin::<SharedCipherSuite>::start(&mut OsRng, b"whatever").unwrap();
        let resp = server
            .post("/v1/auth/login/start")
            .bytes(
                postcard::to_stdvec(&LoginStartRequest {
                    username: "ghost-user".into(),
                    credential_req: login.message.serialize().to_vec(),
                })
                .unwrap()
                .into(),
            )
            .await;
        // A missing user yields a well-formed dummy response, not a 404.
        resp.assert_status_ok();
        let body: LoginStartResponse = postcard::from_bytes(resp.as_bytes()).unwrap();
        assert!(!body.credential_response.is_empty());
    }
}
