//! HTTP transport for the auth flows. Kept separate from `auth.rs` so that module
//! stays pure and unit-testable: `auth` builds/consumes the wire DTOs, `net` moves
//! them over the wire.

use anyhow::Context;
use reqwest::Client;
use tracing::error;
use zeroize::Zeroizing;

use todoers_types::{
    FinishRegisterResponse, LoginFinishResponse, LoginStartResponse, StartRegisterResponse,
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
