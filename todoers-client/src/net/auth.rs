//! HTTP transport for the auth flows. Kept separate from `auth.rs` so that module
//! stays pure and unit-testable: `auth` builds/consumes the wire DTOs, `net` moves
//! them over the wire.

use std::path::Path;

use reqwest::Method;
use tracing::error;
use zeroize::Zeroizing;

use todoers_types::{
    DeviceId, DeviceInfo, DeviceLoginFinishRequest, DeviceLoginFinishResponse,
    DeviceLoginStartRequest, DeviceLoginStartResponse, Ed25519Pub, EnrollDeviceRequest,
    FinishRegisterResponse, ListDevicesResponse, LoginFinishResponse, LoginStartResponse, MemberId,
    StartRegisterResponse, UserPubkeysDto,
};

use super::{Net, decode, unit};
use crate::auth::{self, AccountRow, NewAccount, UnlockedKeys};
use crate::error::{TodoersError, TodoersResult};

#[tracing::instrument(skip(account, password))]
pub async fn local_unlock(
    e: Option<TodoersError>,
    account: Option<&Zeroizing<AccountRow>>,
    password: &str,
) -> TodoersResult<Zeroizing<UnlockedKeys>> {
    let e = e
        .map(|e| TodoersError::OnlineLogin(format!("{e:?}")))
        .unwrap_or_else(|| TodoersError::OnlineLogin("unknown reason".into()));

    // No local account on this device → there's no offline copy to fall back to,
    // so surface the original online-login error.
    let Some(account) = account else {
        return Err(e);
    };
    error!(?e, "Error during login");
    let account = account.clone();
    let password = Zeroizing::new(password.to_string());
    tokio::task::spawn_blocking(move || auth::unlock_offline(password, account))
        .await
        .map_err(TodoersError::from)
        .and_then(|r| r)
        .inspect_err(|e| error!(?e, "Failed to unlock secret keys offline"))
}

impl Net {
    /// Run the full two-message OPAQUE registration against `base_url` and return the
    /// local `NewAccount` to persist. Network/server failures (including a duplicate
    /// username, which the server returns as a 4xx) surface as `Err`.
    #[tracing::instrument(skip(self, password))]
    pub async fn register(&self, username: &str, password: &str) -> TodoersResult<NewAccount> {
        let (flow, start_req) = auth::register_begin(username, password)?;

        let start_resp: StartRegisterResponse = decode(
            self.req(Method::POST, "auth/register/start", None)
                .body(postcard::to_stdvec(&start_req)?),
        )
        .await?;

        // `register_finish` derives the local master key with Argon2id (CPU-bound);
        // keep it off the async worker thread.
        let (finish_req, account) =
            tokio::task::spawn_blocking(move || auth::register_finish(flow, start_resp)).await??;

        let _finish_resp: FinishRegisterResponse = decode(
            self.req(Method::POST, "auth/register/finish", None)
                .body(postcard::to_stdvec(&finish_req)?),
        )
        .await?;

        Ok(account)
    }

    /// Run the full two-message OPAQUE login against `base_url` and recover the
    /// secret keys from the server-held escrow. `account` is only the OFFLINE
    /// fallback: when present, OPAQUE/network failures fall back to a local unlock;
    /// when `None` (a fresh device with no local account), those failures surface as
    /// `Err`. Online login itself needs no local account.
    #[tracing::instrument(skip(self, password))]
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        account: Option<&Zeroizing<AccountRow>>,
    ) -> TodoersResult<Zeroizing<UnlockedKeys>> {
        // Each step's error must route to `local_unlock` (offline fallback), so bind
        // the `Result` WITHOUT `?` and `match` it — a `?` here would propagate out of
        // `login` instead, skipping the fallback entirely.
        let (flow, start_req) = match auth::login_begin(username, password) {
            Ok(v) => v,
            Err(e) => {
                error!(?e, "Failed to start login, falling back to local unlock");
                return local_unlock(Some(e), account, password).await;
            }
        };

        let start_resp: LoginStartResponse = match decode(
            self.req(Method::POST, "auth/login/start", None)
                .body(postcard::to_stdvec(&start_req)?),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                error!(
                    ?e,
                    "Failed to send login/start request, falling back to local unlock"
                );
                return local_unlock(Some(e), account, password).await;
            }
        };

        // `login_finish` derives the local master key with Argon2id (CPU-bound);
        // keep it off the async worker thread.
        let (finish_req, export_key) =
            match tokio::task::spawn_blocking(move || auth::login_finish(flow, start_resp))
                .await
                .map_err(TodoersError::from)
                .and_then(|r| r)
            {
                Ok(v) => v,
                Err(e) => {
                    error!(?e, "Failed to finish login, falling back to local unlock");
                    return local_unlock(Some(e), account, password).await;
                }
            };

        let finish_resp: LoginFinishResponse = match decode(
            self.req(Method::POST, "auth/login/finish", None)
                .body(postcard::to_stdvec(&finish_req)?),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                error!(
                    ?e,
                    "Failed to send login/finish request, falling back to local unlock"
                );
                return local_unlock(Some(e), account, password).await;
            }
        };

        match tokio::task::spawn_blocking(move || {
            auth::unlock_from_escrow(&export_key, finish_resp)
        })
        .await
        .map_err(TodoersError::from)
        .and_then(|r| r)
        {
            Ok(keys) => Ok(keys),
            Err(e) => {
                error!(
                    ?e,
                    "Failed to unlock secret keys from escrow, falling back to local unlock"
                );
                local_unlock(Some(e), account, password).await
            }
        }
    }

    // ── Password-less device unlock (trusted device keys) ─────────────────────────

    /// Enroll this device's Ed25519 trusted key with the server. Authenticated with
    /// the current session `token` (typically obtained from a password login).
    #[tracing::instrument(skip(self, token, device_signing_pub))]
    pub async fn enroll_device(
        &self,
        token: &str,
        device_id: &DeviceId,
        device_signing_pub: &Ed25519Pub,
        label: &str,
    ) -> TodoersResult<()> {
        let req = EnrollDeviceRequest {
            device_id: *device_id,
            device_signing_pub: device_signing_pub.clone(),
            label: label.to_string(),
        };
        unit(
            self.req(Method::POST, "auth/devices", Some(token))
                .body(postcard::to_stdvec(&req)?),
        )
        .await
    }

    /// Revoke this device's session server-side (per-device logout). The caller
    /// should also drop the in-memory token afterward.
    #[tracing::instrument(skip(self, token))]
    pub async fn logout(&self, token: &str) -> TodoersResult<()> {
        unit(self.req(Method::POST, "auth/logout", Some(token))).await
    }

    /// List this account's enrolled devices.
    #[tracing::instrument(skip(self, token))]
    pub async fn list_devices(&self, token: &str) -> TodoersResult<Vec<DeviceInfo>> {
        let resp: ListDevicesResponse =
            decode(self.req(Method::GET, "auth/devices", Some(token))).await?;
        Ok(resp.devices)
    }

    /// Look up another user's public keys by username, to seal a list DEK to them
    /// when sharing. The only list/membership endpoint the client calls before the
    /// full sync phase. A missing user surfaces as a 4xx → `Err`.
    #[tracing::instrument(skip(self, token))]
    pub async fn lookup_pubkeys(
        &self,
        token: &str,
        username: &str,
    ) -> TodoersResult<UserPubkeysDto> {
        decode(
            self.req(Method::PUT, "users/pubkeys", Some(token))
                .body(postcard::to_stdvec(&username.to_string())?),
        )
        .await
    }

    /// Revoke a device (compromise kill-switch). The server then rejects its logins.
    #[tracing::instrument(skip(self, token))]
    pub async fn revoke_device(&self, token: &str, device_id: &DeviceId) -> TodoersResult<()> {
        unit(
            self.req(Method::DELETE, "auth/devices", Some(token))
                .body(postcard::to_stdvec(device_id)?),
        )
        .await
    }

    /// Two-message password-less device login: fetch a challenge, sign it with the
    /// device-auth seed, and exchange it for a fresh session token.
    #[tracing::instrument(skip(self, device_signing_seed))]
    pub async fn device_login(
        &self,
        member_id: &MemberId,
        device_id: &DeviceId,
        device_signing_seed: &[u8; 32],
    ) -> TodoersResult<DeviceLoginFinishResponse> {
        let start: DeviceLoginStartResponse = decode(
            self.req(Method::POST, "auth/device-login/start", None)
                .body(postcard::to_stdvec(&DeviceLoginStartRequest {
                    member_id: *member_id,
                    device_id: *device_id,
                })?),
        )
        .await?;

        let signature = crate::crypto::sign_device_challenge(
            device_signing_seed,
            member_id,
            device_id,
            &start.challenge,
        );

        decode(
            self.req(Method::POST, "auth/device-login/finish", None)
                .body(postcard::to_stdvec(&DeviceLoginFinishRequest {
                    login_id: start.login_id,
                    signature: signature.into(),
                })?),
        )
        .await
    }

    /// Full password-less unlock: decrypt the on-disk cache with the local AGE/SSH
    /// identity to recover the keys + device-auth key, then device-login for a fresh
    /// token. If the server is unreachable, returns the cached keys with an empty
    /// token (offline unlock) rather than failing.
    #[tracing::instrument(skip(self, blob))]
    pub async fn unlock_via_device<P: AsRef<Path> + std::fmt::Debug>(
        &self,
        identity_path: P,
        device_id: &DeviceId,
        blob: Vec<u8>,
    ) -> TodoersResult<Zeroizing<UnlockedKeys>> {
        let identity_contents = tokio::fs::read_to_string(identity_path.as_ref())
            .await
            .map_err(TodoersError::DeviceId)?;

        // KEM decapsulation + AEAD are blocking; keep them off the loop.
        let payload = tokio::task::spawn_blocking(move || {
            auth::unlock_from_device_cache(&identity_contents, &blob)
        })
        .await??;

        let mut keys = payload.keys.clone();
        match self
            .device_login(&keys.member_id, device_id, &payload.device_signing_seed)
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
    #[tracing::instrument(skip(self, token, keys))]
    pub async fn enroll_this_device(
        &self,
        token: &str,
        recipient: &str,
        keys: &UnlockedKeys,
        label: &str,
    ) -> TodoersResult<(DeviceId, Vec<u8>)> {
        let (device_id, device_seed, device_pub) = auth::generate_device_identity();

        let keys = keys.clone();
        let recipient = recipient.to_string();
        let dev_pub = device_pub.clone();
        let blob = tokio::task::spawn_blocking(move || {
            auth::build_device_cache(&recipient, &keys, &device_id, &device_seed, &dev_pub)
        })
        .await??;

        self.enroll_device(token, &device_id, &device_pub, label)
            .await?;
        Ok((device_id, blob))
    }
}

#[cfg(test)]
mod tests {
    use todoers_types::MemberId;
    use zeroize::Zeroizing;

    use crate::auth::{AccountRow, UnlockedKeys, build_local_account};
    use crate::crypto;
    use crate::net::Net;

    /// When the server is unreachable but a local account exists, `login` must fall
    /// back to an OFFLINE unlock and still recover the keys — not propagate the
    /// network error. Regression test for the unreachable `Err => local_unlock`
    /// fallback arms (the `?`-inside-`{ Ok(..) }` scoping bug).
    #[tokio::test]
    async fn login_falls_back_to_offline_unlock_when_server_unreachable() {
        let (username, password) = ("alice", "correct horse battery staple");

        // Build an unlocked identity and persist its local (Argon2id-wrapped) copy,
        // exactly as a real device would after its first online login.
        let (identity_secret, identity_pub) = crypto::generate_identity();
        let (signing_seed, signing_pub) = crypto::generate_signing();
        let member_id = MemberId::from_identity_pub(&identity_pub);
        let keys = UnlockedKeys {
            member_id,
            identity_secret,
            identity_pub,
            signing_seed,
            signing_pub,
            token: String::new(),
        };
        let acct = build_local_account(username, password, &keys).unwrap();
        let row = Zeroizing::new(AccountRow {
            member_id: acct.member_id,
            username: acct.username,
            identity_pub: acct.identity_pub,
            signing_pub: acct.signing_pub,
            wrapped_secret_keys: acct.wrapped_secret_keys,
            kdf_salt: acct.kdf_salt,
            kdf_mem_kib: acct.kdf_mem_kib,
            kdf_iters: acct.kdf_iters,
            kdf_parallelism: acct.kdf_parallelism,
        });

        // Port 1 is closed → the login/start POST fails with a connection error,
        // exercising the network-failure → offline-fallback path deterministically.
        let net = Net::new("http://127.0.0.1:1").unwrap();
        let unlocked = net
            .login(username, password, Some(&row))
            .await
            .expect("network failure with a local account must fall back to offline unlock");

        assert_eq!(unlocked.member_id, keys.member_id);
        assert_eq!(unlocked.identity_secret, keys.identity_secret);
        assert_eq!(unlocked.signing_seed, keys.signing_seed);
        assert!(unlocked.token.is_empty(), "offline unlock yields no token");
    }
}
