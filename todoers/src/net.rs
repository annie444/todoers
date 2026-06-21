//! HTTP transport for the auth flows. Kept separate from `auth.rs` so that module
//! stays pure and unit-testable: `auth` builds/consumes the wire DTOs, `net` moves
//! them over the wire.

use std::path::Path;

use anyhow::Context;
use reqwest::Client;
use tracing::error;
use uuid::Uuid;
use zeroize::Zeroizing;

use todoers_types::{
    DeviceInfo, DeviceLoginFinishRequest, DeviceLoginFinishResponse, DeviceLoginStartRequest,
    DeviceLoginStartResponse, EnrollDeviceRequest, FinishRegisterResponse, ListDevicesResponse,
    LoginFinishResponse, LoginStartResponse, StartRegisterResponse, UserPubkeysDto,
};

use crate::auth::{self, AccountRow, NewAccount, UnlockedKeys};

/// Run the full two-message OPAQUE registration against `base_url` and return the
/// local `NewAccount` to persist. Network/server failures (including a duplicate
/// username, which the server returns as a 4xx) surface as `Err`.
#[tracing::instrument(skip(password))]
pub async fn register(
    base_url: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<NewAccount> {
    let base = base_url.trim_end_matches('/');
    let client = Client::new();

    let (flow, start_req) =
        auth::register_begin(username, password).context("failed to start registration")?;

    let start_resp: StartRegisterResponse = client
        .post(format!("{base}/v1/auth/register/start"))
        .json(&start_req)
        .send()
        .await
        .context("register/start request failed")?
        .error_for_status()
        .context("register/start rejected by server")?
        .json()
        .await
        .context("invalid register/start response")?;

    // `register_finish` derives the local master key with Argon2id (CPU-bound);
    // keep it off the async worker thread.
    let (finish_req, account) =
        tokio::task::spawn_blocking(move || auth::register_finish(flow, start_resp))
            .await
            .context("registration task panicked")?
            .context("failed to finish registration")?;

    let _finish_resp: FinishRegisterResponse = client
        .post(format!("{base}/v1/auth/register/finish"))
        .json(&finish_req)
        .send()
        .await
        .context("register/finish request failed")?
        .error_for_status()
        .context("register/finish rejected by server")?
        .json()
        .await
        .context("invalid register/finish response")?;

    Ok(account)
}

/// Run the full two-message OPAQUE login against `base_url` and recover the
/// secret keys from the server-held escrow. `account` is only the OFFLINE
/// fallback: when present, OPAQUE/network failures fall back to a local unlock;
/// when `None` (a fresh device with no local account), those failures surface as
/// `Err`. Online login itself needs no local account.
#[tracing::instrument(skip(password))]
pub async fn login(
    base_url: &str,
    username: &str,
    password: &str,
    account: Option<&Zeroizing<AccountRow>>,
) -> anyhow::Result<Zeroizing<UnlockedKeys>> {
    let base = base_url.trim_end_matches('/');
    let client = Client::new();

    let (flow, start_req) =
        match auth::login_begin(username, password).context("failed to start registration") {
            Ok(v) => v,
            Err(e) => {
                error!(?e, "Failed to start login, falling back to local unlock");
                return local_unlock(Some(e), account, password).await;
            }
        };

    let start_resp: LoginStartResponse = match {
        Ok(client
            .post(format!("{base}/v1/auth/login/start"))
            .json(&start_req)
            .send()
            .await
            .context("login/start request failed")?
            .error_for_status()
            .context("login/start rejected by server")?
            .json()
            .await
            .context("invalid login/start response")?)
    } {
        Ok(v) => v,
        Err(e) => {
            error!(
                ?e,
                "Failed to send login/start request, falling back to local unlock"
            );
            return local_unlock(Some(e), account, password).await;
        }
    };

    // `register_finish` derives the local master key with Argon2id (CPU-bound);
    // keep it off the async worker thread.
    let (finish_req, export_key) = match {
        Ok(
            tokio::task::spawn_blocking(move || auth::login_finish(flow, start_resp))
                .await
                .context("login task panicked")?
                .context("failed to finish login")?,
        )
    } {
        Ok(v) => v,
        Err(e) => {
            error!(?e, "Failed to finish login, falling back to local unlock");
            return local_unlock(Some(e), account, password).await;
        }
    };

    let finish_resp: LoginFinishResponse = match {
        Ok(client
            .post(format!("{base}/v1/auth/login/finish"))
            .json(&finish_req)
            .send()
            .await
            .context("login/finish request failed")?
            .error_for_status()
            .context("login/finish rejected by server")?
            .json()
            .await
            .context("invalid login/finish response")?)
    } {
        Ok(v) => v,
        Err(e) => {
            error!(
                ?e,
                "Failed to send login/finish request, falling back to local unlock"
            );
            return local_unlock(Some(e), account, password).await;
        }
    };

    let keys = match {
        Ok(
            tokio::task::spawn_blocking(move || auth::unlock_from_escrow(&export_key, finish_resp))
                .await
                .context("unlock task panicked")?
                .context("failed to unlock secret keys")?,
        )
    } {
        Ok(v) => v,
        Err(e) => {
            error!(
                ?e,
                "Failed to unlock secret keys from escrow, falling back to local unlock"
            );
            return local_unlock(Some(e), account, password).await;
        }
    };

    Ok(keys)
}

#[tracing::instrument(skip(password))]
pub async fn local_unlock(
    e: Option<anyhow::Error>,
    account: Option<&Zeroizing<AccountRow>>,
    password: &str,
) -> anyhow::Result<Zeroizing<UnlockedKeys>> {
    let e = e
        .map(|e| e.context("online login failed"))
        .unwrap_or_else(|| anyhow::anyhow!("online login failed for unknown reason"));
    // No local account on this device → there's no offline copy to fall back to,
    // so surface the original online-login error.
    let Some(account) = account else {
        return Err(e);
    };
    error!(?e, "Error during login");
    let account = account.clone();
    let password = Zeroizing::new(password.to_string());
    let keys = match {
        Ok(
            tokio::task::spawn_blocking(move || auth::unlock_offline(password, account))
                .await
                .context("key generation panicked")?
                .context("failed to unlock secret keys offline")?,
        )
    } {
        Ok(v) => v,
        Err(e) => {
            error!(?e, "Failed to unlock secret keys offline");
            return Err(e);
        }
    };
    Ok(keys)
}

// ── Password-less device unlock (trusted device keys) ─────────────────────────

/// Enroll this device's Ed25519 trusted key with the server. Authenticated with
/// the current session `token` (typically obtained from a password login).
#[tracing::instrument(skip(token, device_signing_pub))]
pub async fn enroll_device(
    base_url: &str,
    token: &str,
    device_id: Uuid,
    device_signing_pub: [u8; 32],
    label: &str,
) -> anyhow::Result<()> {
    let base = base_url.trim_end_matches('/');
    Client::new()
        .post(format!("{base}/v1/auth/devices"))
        .bearer_auth(token)
        .json(&EnrollDeviceRequest {
            device_id,
            device_signing_pub,
            label: label.to_string(),
        })
        .send()
        .await
        .context("device enroll request failed")?
        .error_for_status()
        .context("device enroll rejected by server")?;
    Ok(())
}

/// List this account's enrolled devices.
#[tracing::instrument(skip(token))]
pub async fn list_devices(base_url: &str, token: &str) -> anyhow::Result<Vec<DeviceInfo>> {
    let base = base_url.trim_end_matches('/');
    let resp: ListDevicesResponse = Client::new()
        .get(format!("{base}/v1/auth/devices"))
        .bearer_auth(token)
        .send()
        .await
        .context("list devices request failed")?
        .error_for_status()
        .context("list devices rejected by server")?
        .json()
        .await
        .context("invalid list devices response")?;
    Ok(resp.devices)
}

/// Look up another user's public keys by username, to seal a list DEK to them
/// when sharing. The only list/membership endpoint the client calls before the
/// full sync phase. A missing user surfaces as a 4xx → `Err`.
#[tracing::instrument(skip(token))]
pub async fn lookup_pubkeys(
    base_url: &str,
    token: &str,
    username: &str,
) -> anyhow::Result<UserPubkeysDto> {
    let base = base_url.trim_end_matches('/');
    let resp: UserPubkeysDto = Client::new()
        .get(format!("{base}/v1/users/{username}/pubkeys"))
        .bearer_auth(token)
        .send()
        .await
        .context("pubkey lookup request failed")?
        .error_for_status()
        .context("no such user")?
        .json()
        .await
        .context("invalid pubkey lookup response")?;
    Ok(resp)
}

/// Revoke a device (compromise kill-switch). The server then rejects its logins.
#[tracing::instrument(skip(token))]
pub async fn revoke_device(base_url: &str, token: &str, device_id: Uuid) -> anyhow::Result<()> {
    let base = base_url.trim_end_matches('/');
    Client::new()
        .delete(format!("{base}/v1/auth/devices/{device_id}"))
        .bearer_auth(token)
        .send()
        .await
        .context("revoke device request failed")?
        .error_for_status()
        .context("revoke device rejected by server")?;
    Ok(())
}

/// Two-message password-less device login: fetch a challenge, sign it with the
/// device-auth seed, and exchange it for a fresh session token.
#[tracing::instrument(skip(device_signing_seed))]
pub async fn device_login(
    base_url: &str,
    member_id: Uuid,
    device_id: Uuid,
    device_signing_seed: &[u8; 32],
) -> anyhow::Result<DeviceLoginFinishResponse> {
    let base = base_url.trim_end_matches('/');
    let client = Client::new();

    let start: DeviceLoginStartResponse = client
        .post(format!("{base}/v1/auth/device-login/start"))
        .json(&DeviceLoginStartRequest {
            member_id,
            device_id,
        })
        .send()
        .await
        .context("device-login/start request failed")?
        .error_for_status()
        .context("device-login/start rejected by server")?
        .json()
        .await
        .context("invalid device-login/start response")?;

    let signature = crate::crypto::sign_device_challenge(
        device_signing_seed,
        &member_id,
        &device_id,
        &start.challenge,
    );

    let finish: DeviceLoginFinishResponse = client
        .post(format!("{base}/v1/auth/device-login/finish"))
        .json(&DeviceLoginFinishRequest {
            login_id: start.login_id,
            signature,
        })
        .send()
        .await
        .context("device-login/finish request failed")?
        .error_for_status()
        .context("device-login/finish rejected by server")?
        .json()
        .await
        .context("invalid device-login/finish response")?;
    Ok(finish)
}

/// Full password-less unlock: decrypt the on-disk cache with the local AGE/SSH
/// identity to recover the keys + device-auth key, then device-login for a fresh
/// token. If the server is unreachable, returns the cached keys with an empty
/// token (offline unlock) rather than failing.
#[tracing::instrument(skip(blob))]
pub async fn unlock_via_device<P: AsRef<Path> + std::fmt::Debug>(
    base_url: &str,
    identity_path: P,
    device_id: [u8; 16],
    blob: Vec<u8>,
) -> anyhow::Result<Zeroizing<UnlockedKeys>> {
    let identity_contents = tokio::fs::read_to_string(identity_path.as_ref())
        .await
        .with_context(|| {
            format!(
                "reading device identity file {}",
                identity_path.as_ref().display()
            )
        })?;

    // KEM decapsulation + AEAD are blocking; keep them off the loop.
    let payload = tokio::task::spawn_blocking(move || {
        auth::unlock_from_device_cache(&identity_contents, &blob)
    })
    .await
    .context("device unlock task panicked")?
    .context("failed to decrypt device cache")?;

    let member_uuid = Uuid::from_bytes(payload.keys.member_id.0);
    let device_uuid = Uuid::from_bytes(payload.device_id);

    let mut keys = payload.keys.clone();
    match device_login(
        base_url,
        member_uuid,
        device_uuid,
        &payload.device_signing_seed,
    )
    .await
    {
        Ok(resp) => keys.token = resp.token,
        Err(e) => {
            error!(
                ?e,
                "device login failed; continuing offline with cached keys"
            );
            keys.token = String::new();
        }
    }
    Ok(Zeroizing::new(keys))
}

/// Generate a device-auth keypair, seal the keys to `recipient`, and enroll the
/// trusted key with the server. Returns `(device_id, sealed_blob)` for the caller
/// to persist locally. The device-auth private seed lives ONLY inside the blob.
#[tracing::instrument(skip(token, keys))]
pub async fn enroll_this_device(
    base_url: &str,
    token: &str,
    recipient: &str,
    keys: &UnlockedKeys,
    label: &str,
) -> anyhow::Result<([u8; 16], Vec<u8>)> {
    let (device_id, device_seed, device_pub) = auth::generate_device_identity();

    let keys = keys.clone();
    let recipient = recipient.to_string();
    let blob = tokio::task::spawn_blocking(move || {
        auth::build_device_cache(&recipient, &keys, device_id, device_seed, device_pub)
    })
    .await
    .context("device cache sealing panicked")?
    .context("failed to seal device cache")?;

    enroll_device(
        base_url,
        token,
        Uuid::from_bytes(device_id),
        device_pub,
        label,
    )
    .await?;
    Ok((device_id, blob))
}
