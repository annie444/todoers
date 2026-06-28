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

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use old_rand_core::OsRng;
use time::OffsetDateTime;
use tracing::error;

use todoers_types::{
    DEVICE_CHALLENGE_VERSION, DeviceId, DeviceLoginFinishRequest, DeviceLoginFinishResponse,
    DeviceLoginStartRequest, DeviceLoginStartResponse, EnrollDeviceRequest, ListDevicesResponse,
    Nonce, device_challenge_view,
};

use crate::error::{AppError, AppResult};
use crate::routes::auth::{AuthMember, SESSION_TTL, mint_session_token};
use crate::state::AppState;

/// `POST /v1/auth/devices` — enroll this device's trusted Ed25519 key. Requires a
/// valid session (typically a password login on the device being enrolled).
pub async fn enroll(
    State(state): State<AppState>,
    auth: AuthMember,
    bytes: Bytes,
) -> AppResult<StatusCode> {
    let req: EnrollDeviceRequest = postcard::from_bytes(&bytes)?;
    // Enrolling a durable password-less credential is sensitive: require a recent
    // password login (never a device-minted session).
    auth.require_password_step_up()?;
    state
        .db
        .enroll_trusted_device_key(
            &auth.member_id,
            &req.device_id,
            &req.device_signing_pub,
            &req.label,
        )
        .await?;
    Ok(StatusCode::CREATED)
}

/// `GET /v1/auth/devices` — list the caller's enrolled devices.
pub async fn list_devices(State(state): State<AppState>, auth: AuthMember) -> AppResult<Bytes> {
    let devices = state.db.list_trusted_device_keys(&auth.member_id).await?;
    Ok(Bytes::from(postcard::to_stdvec(&ListDevicesResponse {
        devices,
    })?))
}

/// `DELETE /v1/auth/devices` — revoke a device (compromise kill-switch).
pub async fn revoke(
    State(state): State<AppState>,
    auth: AuthMember,
    device_id: Bytes,
) -> AppResult<StatusCode> {
    let device_id: DeviceId = postcard::from_bytes(&device_id)?;
    // Revocation is the compromise kill-switch: also gate it behind step-up so a
    // compromised device can't revoke the owner's other devices.
    auth.require_password_step_up()?;
    state
        .db
        .revoke_trusted_device_key(&auth.member_id, &device_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/auth/device-login/start` — issue a challenge, but only for an
/// enrolled, non-revoked device. A stashed `device_id ‖ nonce` lets finish recover
/// the exact context to verify.
pub async fn login_start(State(state): State<AppState>, bytes: Bytes) -> AppResult<Bytes> {
    let req: DeviceLoginStartRequest = postcard::from_bytes(&bytes)?;
    // Reject unknown/revoked devices up front: nothing to authenticate against.
    state
        .db
        .fetch_active_device_pub(&req.member_id, &req.device_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let mut rng = OsRng;
    let nonce = Nonce::generate(&mut rng);
    let mut stash = Vec::with_capacity(16 + nonce.len());
    stash.extend_from_slice(req.device_id.as_ref());
    stash.extend_from_slice(nonce.as_ref());
    let login_id = state.db.login_start(&stash, Some(req.member_id)).await?;

    Ok(Bytes::from(postcard::to_stdvec(
        &DeviceLoginStartResponse {
            login_id,
            challenge: nonce,
        },
    )?))
}

/// `POST /v1/auth/device-login/finish` — verify the signed challenge and mint a
/// session. Consumes the challenge (so a `login_id` can't be replayed).
pub async fn login_finish(State(state): State<AppState>, bytes: Bytes) -> AppResult<Bytes> {
    let req: DeviceLoginFinishRequest = postcard::from_bytes(&bytes)?;
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
    let device_id = DeviceId::try_from(device_bytes).map_err(|_| AppError::Unauthorized)?;
    let nonce = Nonce::try_from(nonce).map_err(|_| AppError::Unauthorized)?;

    let device_pub = state
        .db
        .fetch_active_device_pub(&member_id, &device_id)
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
        let msg = device_challenge_view(DEVICE_CHALLENGE_VERSION, &member_id, &device_id, &nonce);
        vk.verify(&msg, &sig).map_err(|_| AppError::Unauthorized)?;
    }

    let keys = state
        .db
        .fetch_user_keys(&member_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let (token, token_hash) = mint_session_token();
    let expires_at = OffsetDateTime::now_utc() + SESSION_TTL;
    // Tag the session with this device so revocation can kill it and step-up auth
    // can tell it apart from a password login.
    state
        .db
        .create_session(&member_id, &token_hash, expires_at, Some(&device_id))
        .await?;

    Ok(Bytes::from(postcard::to_stdvec(
        &DeviceLoginFinishResponse {
            token,
            member_id,
            identity_pub: keys.identity_pub,
            signing_pub: keys.signing_pub,
        },
    )?))
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
        DeviceLoginStartResponse, Ed25519Pub, EnrollDeviceRequest, ListDevicesResponse, MemberId,
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
        let device_id = DeviceId::generate(&mut rng);
        server
            .post("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .bytes(
                postcard::to_stdvec(&EnrollDeviceRequest {
                    device_id,
                    device_signing_pub: Ed25519Pub::new(*device_key.verifying_key().as_bytes()),
                    label: "laptop".into(),
                })
                .unwrap()
                .into(),
            )
            .await
            .assert_status(StatusCode::CREATED);

        // It shows up in the device list.
        let resp = server
            .get("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .await;
        resp.assert_status_ok();
        let devices: ListDevicesResponse = postcard::from_bytes(resp.as_bytes()).unwrap();
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
            .delete("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .bytes(Bytes::from(postcard::to_stdvec(&device_id).unwrap()))
            .await
            .assert_status(StatusCode::NO_CONTENT);

        assert!(
            do_device_login(&server, member_id, device_id, &device_key)
                .await
                .is_none(),
            "device login must be rejected after revocation"
        );
    }

    /// Step-up: a device-minted session must NOT be able to enroll another device
    /// (prevents a compromised device from escalating), and revoking a device must
    /// immediately kill the session it minted (per-device session tagging).
    #[sqlx::test(migrations = "db/migrations")]
    async fn step_up_and_session_tagging(db: sqlx::PgPool) {
        let state = crate::state::AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);

        let pw_token = crate::routes::testutil::register_and_login(&server, "dev3", "pw").await;
        let login = crate::routes::testutil::login(&server, "dev3", "pw").await;
        let member_id = login.member_id;

        // Enroll a device with the (fresh) password session.
        let mut rng = OsRng;
        let device_key = SigningKey::generate(&mut rng);
        let device_id = DeviceId::generate(&mut rng);
        server
            .post("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {pw_token}"))
            .bytes(
                postcard::to_stdvec(&EnrollDeviceRequest {
                    device_id,
                    device_signing_pub: Ed25519Pub::new(device_key.verifying_key().to_bytes()),
                    label: "laptop".into(),
                })
                .unwrap()
                .into(),
            )
            .await
            .assert_status(StatusCode::CREATED);

        // Get a DEVICE session, then confirm it can read but cannot enroll.
        let device_token = do_device_login(&server, member_id, device_id, &device_key)
            .await
            .expect("device login should succeed");
        // Read-only is fine for a device session.
        server
            .get("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {device_token}"))
            .await
            .assert_status_ok();
        // Enrolling another device from a device session is forbidden (step-up).
        let other_key = SigningKey::generate(&mut rng);
        server
            .post("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {device_token}"))
            .bytes(
                postcard::to_stdvec(&EnrollDeviceRequest {
                    device_id: DeviceId::generate(&mut rng),
                    device_signing_pub: Ed25519Pub::new(other_key.verifying_key().to_bytes()),
                    label: "rogue".into(),
                })
                .unwrap()
                .into(),
            )
            .await
            .assert_status(StatusCode::FORBIDDEN);
        // Revoking from a device session is likewise forbidden.
        server
            .delete("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {device_token}"))
            .bytes(Bytes::from(postcard::to_stdvec(&device_id).unwrap()))
            .await
            .assert_status(StatusCode::FORBIDDEN);

        // Revoke with the password session → the device's live session dies too.
        server
            .delete("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {pw_token}"))
            .bytes(Bytes::from(postcard::to_stdvec(&device_id).unwrap()))
            .await
            .assert_status(StatusCode::NO_CONTENT);
        server
            .get("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {device_token}"))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
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
        let device_id = DeviceId::generate(&mut rng);
        server
            .post("/v1/auth/devices")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .bytes(
                postcard::to_stdvec(&EnrollDeviceRequest {
                    device_id,
                    device_signing_pub: Ed25519Pub::new(device_key.verifying_key().to_bytes()),
                    label: "laptop".into(),
                })
                .unwrap()
                .into(),
            )
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
        member_id: MemberId,
        device_id: DeviceId,
        device_key: &SigningKey,
    ) -> Option<String> {
        let start = server
            .post("/v1/auth/device-login/start")
            .bytes(
                postcard::to_stdvec(&DeviceLoginStartRequest {
                    member_id,
                    device_id,
                })
                .unwrap()
                .into(),
            )
            .await;
        if start.status_code() != StatusCode::OK {
            return None;
        }
        let start: DeviceLoginStartResponse = postcard::from_bytes(start.as_bytes()).unwrap();

        let msg = device_challenge_view(
            DEVICE_CHALLENGE_VERSION,
            &member_id,
            &device_id,
            &start.challenge,
        );
        let sig = device_key.sign(&msg);

        let finish = server
            .post("/v1/auth/device-login/finish")
            .bytes(
                postcard::to_stdvec(&DeviceLoginFinishRequest {
                    login_id: start.login_id,
                    signature: sig.into(),
                })
                .unwrap()
                .into(),
            )
            .await;
        if finish.status_code() != StatusCode::OK {
            return None;
        }
        let finish: DeviceLoginFinishResponse = postcard::from_bytes(finish.as_bytes()).unwrap();
        Some(finish.token)
    }
}
