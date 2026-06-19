//! Password-less device login — the server side of the "trusted device keys"
//! flow.
//!
//! A device enrolls a dedicated Ed25519 *device-auth* public key (authenticated
//! with an ordinary session). Later it logs in without a password by signing a
//! server-issued challenge with the matching private key, which it recovered from
//! its on-disk encrypted key cache. The server verifies the signature against the
//! enrolled key and mints a session. Revoking the enrolled key makes the server
//! reject that device thereafter — the compromise kill-switch for a stolen cache.
//!
//! The transient challenge reuses the existing `login_cache` (consume-once,
//! expiring): we stash `device_id ‖ nonce` in its `state` column so `login_finish`
//! recovers exactly which device and nonce to verify against.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use old_rand_core::{OsRng, RngCore};
use time::OffsetDateTime;
use tracing::error;
use uuid::Uuid;

use todoers_types::{
    DEVICE_CHALLENGE_VERSION, DeviceLoginFinishRequest, DeviceLoginFinishResponse,
    DeviceLoginStartRequest, DeviceLoginStartResponse, EnrollDeviceRequest, ListDevicesResponse,
    device_challenge_view,
};

use crate::error::{AppError, AppResult};
use crate::routes::auth::{AuthMember, SESSION_TTL, mint_session_token};
use crate::state::AppState;

/// `POST /v1/auth/devices` — enroll this device's trusted Ed25519 key. Requires a
/// valid session (typically a password login on the device being enrolled).
pub async fn enroll(
    State(state): State<AppState>,
    auth: AuthMember,
    Json(req): Json<EnrollDeviceRequest>,
) -> AppResult<StatusCode> {
    state
        .db
        .enroll_trusted_device_key(
            auth.member_id,
            req.device_id,
            &req.device_signing_pub,
            &req.label,
        )
        .await?;
    Ok(StatusCode::CREATED)
}

/// `GET /v1/auth/devices` — list the caller's enrolled devices.
pub async fn list_devices(
    State(state): State<AppState>,
    auth: AuthMember,
) -> AppResult<Json<ListDevicesResponse>> {
    let devices = state.db.list_trusted_device_keys(auth.member_id).await?;
    Ok(Json(ListDevicesResponse { devices }))
}

/// `DELETE /v1/auth/devices/{device_id}` — revoke a device (compromise kill-switch).
pub async fn revoke(
    State(state): State<AppState>,
    auth: AuthMember,
    Path(device_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state
        .db
        .revoke_trusted_device_key(auth.member_id, device_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/auth/device-login/start` — issue a challenge, but only for an
/// enrolled, non-revoked device. A stashed `device_id ‖ nonce` lets finish recover
/// the exact context to verify.
pub async fn login_start(
    State(state): State<AppState>,
    Json(req): Json<DeviceLoginStartRequest>,
) -> AppResult<Json<DeviceLoginStartResponse>> {
    // Reject unknown/revoked devices up front: nothing to authenticate against.
    state
        .db
        .fetch_active_device_pub(req.member_id, req.device_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let mut stash = Vec::with_capacity(16 + nonce.len());
    stash.extend_from_slice(req.device_id.as_bytes());
    stash.extend_from_slice(&nonce);
    let login_id = state.db.login_start(&stash, Some(req.member_id)).await?;

    Ok(Json(DeviceLoginStartResponse {
        login_id,
        challenge: nonce.to_vec(),
    }))
}

/// `POST /v1/auth/device-login/finish` — verify the signed challenge and mint a
/// session. Consumes the challenge (so a `login_id` can't be replayed).
pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<DeviceLoginFinishRequest>,
) -> AppResult<Json<DeviceLoginFinishResponse>> {
    let stash = state
        .db
        .login_finish(req.login_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let member_id = stash.member_id.ok_or(AppError::Unauthorized)?;

    // Recover device_id ‖ nonce from the stashed challenge state.
    if stash.state.len() < 16 {
        return Err(AppError::Unauthorized);
    }
    let (device_bytes, nonce) = stash.state.split_at(16);
    let device_id = Uuid::from_slice(device_bytes).map_err(|_| AppError::Unauthorized)?;

    let device_pub = state
        .db
        .fetch_active_device_pub(member_id, device_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // Mirrors the update path: signature verification is the one bit of
    // "understanding" the blind relay performs, gated by the same config flag.
    if state.verify_signatures {
        let pub_bytes: [u8; 32] = device_pub
            .as_slice()
            .try_into()
            .map_err(|_| AppError::Unauthorized)?;
        let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|e| {
            error!(error = ?e, "stored device key is not a valid Ed25519 key");
            AppError::Unauthorized
        })?;
        let sig = Signature::from_bytes(&req.signature);
        let msg = device_challenge_view(DEVICE_CHALLENGE_VERSION, &member_id, &device_id, nonce);
        vk.verify(&msg, &sig).map_err(|_| AppError::Unauthorized)?;
    }

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

    Ok(Json(DeviceLoginFinishResponse {
        token,
        member_id,
        identity_pub: keys.identity_pub,
        signing_pub: keys.signing_pub,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::http::header::AUTHORIZATION;
    use axum_test::TestServer;
    use ed25519_dalek::{Signer, SigningKey};
    use old_rand_core::OsRng;

    use todoers_types::{
        DeviceLoginFinishRequest, DeviceLoginFinishResponse, DeviceLoginStartRequest,
        DeviceLoginStartResponse, EnrollDeviceRequest, ListDevicesResponse,
    };

    /// End-to-end: enroll a device key, log in password-lessly with it, then revoke
    /// it and confirm the server rejects the next device login.
    #[sqlx::test(migrations = "db/migrations")]
    async fn device_login_round_trip_and_revoke(db: sqlx::PgPool) {
        let state = crate::state::AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);

        // A normal password login to obtain a session + member_id.
        let token = crate::routes::testutil::register_and_login(&server, "device-user", "pw").await;
        let login = crate::routes::testutil::login(&server, "device-user", "pw").await;
        let member_id = login.member_id;

        // Generate the device-auth keypair and enroll its public half.
        let mut rng = OsRng;
        let device_key = SigningKey::generate(&mut rng);
        let device_id = Uuid::new_v4();
        server
            .post("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .json(&EnrollDeviceRequest {
                device_id,
                device_signing_pub: device_key.verifying_key().to_bytes(),
                label: "laptop".into(),
            })
            .await
            .assert_status(StatusCode::CREATED);

        // It shows up in the device list.
        let resp = server
            .get("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .await;
        resp.assert_status_ok();
        let devices: ListDevicesResponse = resp.json();
        assert_eq!(devices.devices.len(), 1);
        assert_eq!(devices.devices[0].device_id, device_id);
        assert!(!devices.devices[0].revoked);

        // ── password-less device login ──
        let device_token = do_device_login(&server, member_id, device_id, &device_key)
            .await
            .expect("device login should succeed for an enrolled device");
        assert!(!device_token.is_empty());

        // The minted token authenticates a real request.
        server
            .post("/v1/auth/logout")
            .add_header(AUTHORIZATION, format!("Bearer {device_token}"))
            .await
            .assert_status_ok();

        // ── revoke, then device login must fail ──
        server
            .delete(&format!("/v1/auth/devices/{device_id}"))
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .await
            .assert_status(StatusCode::NO_CONTENT);

        assert!(
            do_device_login(&server, member_id, device_id, &device_key)
                .await
                .is_none(),
            "device login must be rejected after revocation"
        );
    }

    /// A wrong signature must not authenticate.
    #[sqlx::test(migrations = "db/migrations")]
    async fn device_login_rejects_bad_signature(db: sqlx::PgPool) {
        let state = crate::state::AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        let token = crate::routes::testutil::register_and_login(&server, "dev2", "pw").await;
        let login = crate::routes::testutil::login(&server, "dev2", "pw").await;

        let mut rng = OsRng;
        let device_key = SigningKey::generate(&mut rng);
        let attacker_key = SigningKey::generate(&mut rng);
        let device_id = Uuid::new_v4();
        server
            .post("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .json(&EnrollDeviceRequest {
                device_id,
                device_signing_pub: device_key.verifying_key().to_bytes(),
                label: "laptop".into(),
            })
            .await
            .assert_status(StatusCode::CREATED);

        // Sign the challenge with the WRONG key.
        assert!(
            do_device_login(&server, login.member_id, device_id, &attacker_key)
                .await
                .is_none(),
            "a challenge signed by the wrong key must be rejected"
        );
    }

    /// Drive start → sign → finish. Returns the minted token, or `None` if the
    /// server rejected the device at start or finish.
    async fn do_device_login(
        server: &TestServer,
        member_id: Uuid,
        device_id: Uuid,
        device_key: &SigningKey,
    ) -> Option<String> {
        let start = server
            .post("/v1/auth/device-login/start")
            .json(&DeviceLoginStartRequest {
                member_id,
                device_id,
            })
            .await;
        if start.status_code() != StatusCode::OK {
            return None;
        }
        let start: DeviceLoginStartResponse = start.json();

        let msg = device_challenge_view(
            DEVICE_CHALLENGE_VERSION,
            &member_id,
            &device_id,
            &start.challenge,
        );
        let sig = device_key.sign(&msg);

        let finish = server
            .post("/v1/auth/device-login/finish")
            .json(&DeviceLoginFinishRequest {
                login_id: start.login_id,
                signature: sig.to_bytes(),
            })
            .await;
        if finish.status_code() != StatusCode::OK {
            return None;
        }
        let finish: DeviceLoginFinishResponse = finish.json();
        Some(finish.token)
    }
}
