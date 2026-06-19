//! Client-side OPAQUE auth driver — transport-agnostic.
//!
//! These functions own the password, the OPAQUE handshake, key generation, and
//! the wrapping of the user's private identity. They DO NOT do any I/O: each step
//! returns a wire request DTO for the caller to send and consumes the wire
//! response DTO the caller received. That keeps the whole flow unit-testable
//! without a network (see the tests at the bottom, which play the server side of
//! OPAQUE in-process).
//!
//! Registration produces TWO wrapped copies of the same secret keys:
//!   - the **escrow** copy, sealed under `derive_escrow_key(export_key)`, uploaded
//!     to the server so a fresh device can recover after login;
//!   - the **local** copy, sealed under `derive_local_master(password, salt..)`,
//!     persisted in the SQLite `account` row for OFFLINE unlock.

use old_rand_core::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use todoers_types::{
    Ed25519Pub, FinishRegisterRequest, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, MemberId, SharedCipherSuite, StartRegisterRequest, StartRegisterResponse,
    X25519Pub,
};

use crate::crypto;
use crate::error::{AppError, AppResult};

// Argon2id parameters for the LOCAL (offline) master key. Recorded per-account so
// they can evolve without breaking existing rows. ~19 MiB / 2 passes (OWASP-ish).
pub const KDF_MEM_KIB: u32 = 19_456;
pub const KDF_ITERS: u32 = 2;
pub const KDF_PARALLELISM: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize, Zeroize)]
pub struct KdfSalt(#[serde(with = "todoers_types::b6416")] pub [u8; 16]);

impl AsRef<[u8]> for KdfSalt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8; 16]> for KdfSalt {
    fn as_mut(&mut self) -> &mut [u8; 16] {
        &mut self.0
    }
}

impl From<[u8; 16]> for KdfSalt {
    fn from(arr: [u8; 16]) -> Self {
        KdfSalt(arr)
    }
}

impl From<Vec<u8>> for KdfSalt {
    fn from(vec: Vec<u8>) -> Self {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&vec);
        KdfSalt(bytes)
    }
}

/// In-flight registration state held between `register_begin` and
/// `register_finish`. Carries the freshly generated keypairs and a zeroizing copy
/// of the password (needed again at finish for the OPAQUE Ksf).
pub struct RegisterFlow {
    username: String,
    password: Zeroizing<Vec<u8>>,
    reg_state: ClientRegistration<SharedCipherSuite>,
    identity_secret: [u8; 32],
    identity_pub: X25519Pub,
    signing_seed: [u8; 32],
    signing_pub: Ed25519Pub,
}

/// Everything needed to persist the local `account` row after registration.
pub struct NewAccount {
    pub member_id: MemberId,
    pub username: String,
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
    /// The LOCAL (Argon2id-wrapped) copy of the secret keys.
    pub wrapped_secret_keys: Vec<u8>,
    pub kdf_salt: KdfSalt,
    pub kdf_mem_kib: i64,
    pub kdf_iters: i64,
    pub kdf_parallelism: i64,
}

/// The `account` row as loaded from SQLite (mirror of `NewAccount`, minus the
/// transient nature). Lives here so both `crate::db` and the unlock path share it.
#[derive(Clone, Debug, PartialEq, Eq, Default, sqlx::FromRow, Zeroize)]
pub struct AccountRow {
    pub member_id: MemberId,
    pub username: String,
    pub identity_pub: X25519Pub,
    pub signing_pub: Ed25519Pub,
    pub wrapped_secret_keys: Zeroizing<Vec<u8>>,
    pub kdf_salt: KdfSalt,
    pub kdf_mem_kib: i64,
    pub kdf_iters: i64,
    pub kdf_parallelism: i64,
}

/// The unlocked, in-memory identity. `identity_secret`/`signing_seed` are class-3
/// material: never written back to disk.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, Serialize, Deserialize)]
pub struct UnlockedKeys {
    pub member_id: MemberId,
    pub identity_secret: [u8; 32],
    pub identity_pub: X25519Pub,
    pub signing_seed: [u8; 32],
    pub signing_pub: Ed25519Pub,
    /// Session bearer token (empty for the offline path).
    pub token: String,
}

/// In-flight login state held between `login_begin` and `login_finish`.
pub struct LoginFlow {
    password: Zeroizing<Vec<u8>>,
    login_state: ClientLogin<SharedCipherSuite>,
}

// ── Registration ─────────────────────────────────────────────────────────────

/// Step 1: generate the identity + signing keypairs and the OPAQUE registration
/// request. Returns the flow to carry forward and the request DTO to POST.
#[tracing::instrument(skip(password))]
pub fn register_begin(
    username: &str,
    password: &str,
) -> AppResult<(RegisterFlow, StartRegisterRequest)> {
    let mut rng = OsRng;
    let (identity_secret, identity_pub) = crypto::generate_identity();
    let (signing_seed, signing_pub) = crypto::generate_signing();

    let start = ClientRegistration::<SharedCipherSuite>::start(&mut rng, password.as_bytes())?;
    let request = StartRegisterRequest {
        identity_pub,
        registration_req: start.message.serialize().to_vec(),
    };

    let flow = RegisterFlow {
        username: username.to_string(),
        password: Zeroizing::new(password.as_bytes().to_vec()),
        reg_state: start.state,
        identity_secret,
        identity_pub,
        signing_seed,
        signing_pub,
    };
    Ok((flow, request))
}

/// Step 2: finish OPAQUE registration (yielding `export_key`), wrap the secret
/// keys both ways, and produce the upload request plus the local account record.
#[tracing::instrument(skip(flow, response))]
pub fn register_finish(
    flow: RegisterFlow,
    response: StartRegisterResponse,
) -> AppResult<(FinishRegisterRequest, NewAccount)> {
    let mut rng = OsRng;
    let reg_response = RegistrationResponse::<SharedCipherSuite>::deserialize(&response.response)?;
    let finish = flow.reg_state.finish(
        &mut rng,
        &flow.password,
        reg_response,
        ClientRegistrationFinishParameters::default(),
    )?;

    // Escrow copy: wrapped under the export_key-derived master, sent to the server.
    let escrow_master = crypto::derive_escrow_key(finish.export_key.as_ref());
    let escrow_wrapped =
        crypto::wrap_secret_keys(&escrow_master, &flow.identity_secret, &flow.signing_seed);

    // Local copy: wrapped under an Argon2id master, persisted on device for offline unlock.
    let mut kdf_salt = KdfSalt::default();
    {
        use old_rand_core::RngCore;
        OsRng.fill_bytes(&mut kdf_salt.0);
    }
    let local_master = crypto::derive_local_master(
        &flow.password,
        kdf_salt.as_ref(),
        KDF_MEM_KIB,
        KDF_ITERS,
        KDF_PARALLELISM,
    )?;
    let local_wrapped =
        crypto::wrap_secret_keys(&local_master, &flow.identity_secret, &flow.signing_seed);

    let member_id = MemberId::from_identity_pub(&flow.identity_pub);

    let request = FinishRegisterRequest {
        username: flow.username.clone(),
        identity_pub: flow.identity_pub,
        signing_pub: flow.signing_pub.0,
        wrapped_secret_keys: escrow_wrapped,
        registration_up: finish.message.serialize().to_vec(),
    };
    let account = NewAccount {
        member_id,
        username: flow.username,
        identity_pub: flow.identity_pub,
        signing_pub: flow.signing_pub,
        wrapped_secret_keys: local_wrapped,
        kdf_salt,
        kdf_mem_kib: KDF_MEM_KIB.into(),
        kdf_iters: KDF_ITERS.into(),
        kdf_parallelism: KDF_PARALLELISM.into(),
    };
    Ok((request, account))
}

// ── Login ────────────────────────────────────────────────────────────────────

/// Step 1: start an OPAQUE login. Only the password is needed.
#[tracing::instrument(skip(password))]
pub fn login_begin(username: &str, password: &str) -> AppResult<(LoginFlow, LoginStartRequest)> {
    let mut rng = OsRng;
    let start = ClientLogin::<SharedCipherSuite>::start(&mut rng, password.as_bytes())?;
    let request = LoginStartRequest {
        username: username.to_string(),
        credential_req: start.message.serialize().to_vec(),
    };
    let flow = LoginFlow {
        password: Zeroizing::new(password.as_bytes().to_vec()),
        login_state: start.state,
    };
    Ok((flow, request))
}

/// Step 2: finish the AKE. Returns the finalization request DTO plus the
/// `export_key` (needed to unwrap the escrow blob from the finish response). A
/// wrong password fails here with `AppError::Opaque`.
#[tracing::instrument(skip(flow, response))]
pub fn login_finish(
    flow: LoginFlow,
    response: LoginStartResponse,
) -> AppResult<(LoginFinishRequest, Zeroizing<Vec<u8>>)> {
    let mut rng = OsRng;
    let credential_response =
        CredentialResponse::<SharedCipherSuite>::deserialize(&response.credential_response)?;
    let finish = flow.login_state.finish(
        &mut rng,
        &flow.password,
        credential_response,
        ClientLoginFinishParameters::default(),
    )?;
    // `finish.session_key` proves mutual knowledge; we don't need it — the server
    // hands back its own bearer token in the finish response.
    let export_key = finish.export_key.to_vec().into();
    let request = LoginFinishRequest {
        login_id: response.login_id,
        credential_finalization: finish.message.serialize().to_vec(),
    };
    Ok((request, export_key))
}

/// Recover the in-memory identity from the server-escrowed blob using the
/// `export_key` obtained from `login_finish`.
#[tracing::instrument(skip(response))]
pub fn unlock_from_escrow(
    export_key: &[u8],
    response: LoginFinishResponse,
) -> AppResult<Zeroizing<UnlockedKeys>> {
    let master = crypto::derive_escrow_key(export_key);
    let (identity_secret, signing_seed) =
        crypto::unwrap_secret_keys(&master, &response.wrapped_secret_keys)?;

    let identity_pub = X25519Pub(
        response
            .identity_pub
            .try_into()
            .map_err(|_| AppError::Aead)?,
    );
    let signing_pub = Ed25519Pub(
        response
            .signing_pub
            .try_into()
            .map_err(|_| AppError::Aead)?,
    );

    Ok(Zeroizing::new(UnlockedKeys {
        member_id: MemberId(*response.member_id.as_bytes()),
        identity_secret,
        identity_pub,
        signing_seed,
        signing_pub,
        token: response.token,
    }))
}

/// Recover the in-memory identity from the device-local `account` row using the
/// password — no server needed. A wrong password fails the AEAD tag check.
#[tracing::instrument(skip(password, account))]
pub fn unlock_offline(
    password: Zeroizing<String>,
    account: Zeroizing<AccountRow>,
) -> AppResult<Zeroizing<UnlockedKeys>> {
    let master = crypto::derive_local_master(
        password.as_bytes(),
        account.kdf_salt.as_ref(),
        account.kdf_mem_kib.try_into().unwrap_or(KDF_MEM_KIB),
        account.kdf_iters.try_into().unwrap_or(KDF_ITERS),
        account
            .kdf_parallelism
            .try_into()
            .unwrap_or(KDF_PARALLELISM),
    )?;
    let (identity_secret, signing_seed) =
        crypto::unwrap_secret_keys(&master, &account.wrapped_secret_keys)?;
    Ok(Zeroizing::new(UnlockedKeys {
        member_id: account.member_id,
        identity_secret,
        identity_pub: account.identity_pub,
        signing_seed,
        signing_pub: account.signing_pub,
        token: String::new(),
    }))
}

/// After a fresh-device login recovers the identity from the server escrow,
/// re-wrap those keys under a new Argon2id(password) local master so this device
/// can later unlock OFFLINE. This mirrors the LOCAL-copy half of
/// `register_finish` — the escrow (server) and local (Argon2id) copies are
/// independent wrappings of the same secret keys.
#[tracing::instrument(skip(password, keys))]
pub fn build_local_account(
    username: &str,
    password: &str,
    keys: &UnlockedKeys,
) -> AppResult<NewAccount> {
    let mut kdf_salt = KdfSalt::default();
    {
        use old_rand_core::RngCore;
        OsRng.fill_bytes(&mut kdf_salt.0);
    }
    let local_master = crypto::derive_local_master(
        password.as_bytes(),
        kdf_salt.as_ref(),
        KDF_MEM_KIB,
        KDF_ITERS,
        KDF_PARALLELISM,
    )?;
    let wrapped_secret_keys =
        crypto::wrap_secret_keys(&local_master, &keys.identity_secret, &keys.signing_seed);

    Ok(NewAccount {
        member_id: keys.member_id,
        username: username.to_string(),
        identity_pub: keys.identity_pub,
        signing_pub: keys.signing_pub,
        wrapped_secret_keys,
        kdf_salt,
        kdf_mem_kib: KDF_MEM_KIB.into(),
        kdf_iters: KDF_ITERS.into(),
        kdf_parallelism: KDF_PARALLELISM.into(),
    })
}

// ── Password-less device unlock ───────────────────────────────────────────────
// A THIRD wrapping of the secret keys, alongside escrow (server) and local
// (Argon2id): the unlocked keys are sealed to a local AGE/SSH key for
// password-less unlock. Bundled with them is a dedicated Ed25519 device-auth
// keypair whose public half is enrolled with the server; the private half signs
// the server's device-login challenge so this device can also SYNC without a
// password. Revoking the device server-side then rejects it even if this cache
// (and the local key) were stolen.

/// The plaintext sealed inside the on-disk device cache. Class-3 material: only
/// ever exists decrypted in memory.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
pub struct DeviceCachePayload {
    /// The unlocked identity. Its `token` is always blanked before sealing — a
    /// fresh session is minted via device login, never cached.
    pub keys: UnlockedKeys,
    /// Opaque 16-byte device id, enrolled with the server.
    pub device_id: [u8; 16],
    /// Ed25519 device-auth seed (signs the device-login challenge).
    pub device_signing_seed: [u8; 32],
    /// Ed25519 device-auth public key (enrolled as the server-side trusted key).
    pub device_signing_pub: [u8; 32],
}

/// Generate a fresh device id + Ed25519 device-auth keypair for enrollment.
/// Returns `(device_id, signing_seed, signing_pub)`.
#[tracing::instrument]
pub fn generate_device_identity() -> ([u8; 16], [u8; 32], [u8; 32]) {
    let mut device_id = [0u8; 16];
    {
        use old_rand_core::RngCore;
        OsRng.fill_bytes(&mut device_id);
    }
    let (seed, pubkey) = crypto::generate_signing();
    (device_id, seed, pubkey.0)
}

/// Seal the unlocked keys + device-auth keypair to a local AGE/SSH recipient,
/// producing the on-disk cache blob (class-1, safe at rest).
#[tracing::instrument(skip(keys, device_signing_seed))]
pub fn build_device_cache(
    backend: crypto::DeviceBackend,
    recipient: &str,
    keys: &UnlockedKeys,
    device_id: [u8; 16],
    device_signing_seed: [u8; 32],
    device_signing_pub: [u8; 32],
) -> AppResult<Vec<u8>> {
    let mut keys = keys.clone();
    keys.token.zeroize(); // never cache a live session token
    let payload = DeviceCachePayload {
        keys,
        device_id,
        device_signing_seed,
        device_signing_pub,
    };
    let mut json = serde_json::to_vec(&payload).map_err(|_| AppError::Aead)?;
    let sealed = crypto::device_seal(backend, recipient, &json);
    json.zeroize();
    sealed
}

/// Open the on-disk device cache with the local AGE/SSH identity, recovering the
/// unlocked keys and device-auth keypair. A wrong/absent key fails decryption.
#[tracing::instrument(skip(identity_contents, blob))]
pub fn unlock_from_device_cache(
    backend: crypto::DeviceBackend,
    identity_contents: &str,
    blob: &[u8],
) -> AppResult<Zeroizing<DeviceCachePayload>> {
    let mut json = crypto::device_open(backend, identity_contents, blob)?;
    let payload: DeviceCachePayload =
        serde_json::from_slice(&json).map_err(|_| AppError::Aead)?;
    json.zeroize();
    Ok(Zeroizing::new(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };
    use uuid::Uuid;

    /// Drive the full register → login → unlock cycle, playing the server side of
    /// OPAQUE in-process. Asserts the keys recovered from the escrow blob are the
    /// same ones generated at registration.
    #[test]
    fn escrow_round_trip_recovers_identity() {
        let mut rng = OsRng;
        let setup = ServerSetup::<SharedCipherSuite>::new(&mut rng);
        let (username, password) = ("alice", "correct horse battery staple".to_string());

        // ── registration ──
        let (flow, start_req) = register_begin(username, &password).unwrap();
        let member_id = MemberId::from_identity_pub(&start_req.identity_pub);

        let server_reg_start = ServerRegistration::start(
            &setup,
            RegistrationRequest::<SharedCipherSuite>::deserialize(&start_req.registration_req)
                .unwrap(),
            member_id.as_bytes(),
        )
        .unwrap();
        let start_resp = StartRegisterResponse {
            response: server_reg_start.message.serialize().to_vec(),
        };
        let (finish_req, account) = register_finish(flow, start_resp).unwrap();

        // Server stores the password file.
        let upload =
            RegistrationUpload::<SharedCipherSuite>::deserialize(&finish_req.registration_up)
                .unwrap();
        let password_file = ServerRegistration::finish(upload);

        // ── login ──
        let (lflow, lstart_req) = login_begin(username, &password).unwrap();
        let server_login_start = ServerLogin::start(
            &mut rng,
            &setup,
            Some(password_file),
            CredentialRequest::<SharedCipherSuite>::deserialize(&lstart_req.credential_req)
                .unwrap(),
            member_id.as_bytes(),
            ServerLoginParameters::default(),
        )
        .unwrap();
        let lstart_resp = LoginStartResponse {
            login_id: Uuid::new_v4(),
            credential_response: server_login_start.message.serialize().to_vec(),
        };
        let (lfinish_req, export_key) = login_finish(lflow, lstart_resp).unwrap();

        // Server confirms the AKE (proves the client knew the password).
        server_login_start
            .state
            .finish(
                CredentialFinalization::<SharedCipherSuite>::deserialize(
                    &lfinish_req.credential_finalization,
                )
                .unwrap(),
                ServerLoginParameters::default(),
            )
            .unwrap();

        // The server returns the escrow blob it stored at registration.
        let login_resp = LoginFinishResponse {
            token: "session-token".into(),
            member_id: Uuid::from_bytes(member_id.0),
            identity_pub: finish_req.identity_pub.0.to_vec(),
            signing_pub: finish_req.signing_pub.to_vec(),
            wrapped_secret_keys: finish_req.wrapped_secret_keys.clone(),
        };
        let unlocked = unlock_from_escrow(&export_key, login_resp).unwrap();

        // The recovered secrets must reproduce the registered public keys.
        let recovered_id_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            unlocked.identity_secret,
        ))
        .to_bytes();
        assert_eq!(X25519Pub(recovered_id_pub), account.identity_pub);
        let recovered_sign_pub = ed25519_dalek::SigningKey::from_bytes(&unlocked.signing_seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(Ed25519Pub(recovered_sign_pub), account.signing_pub);
        assert_eq!(unlocked.member_id, member_id);
        assert_eq!(unlocked.token, "session-token");

        // ── a fresh device persists its own local copy from the escrow unlock ──
        // `build_local_account` re-wraps the recovered keys under Argon2id(password)
        // so a later OFFLINE unlock reproduces the same secrets.
        let fresh = build_local_account(username, &password, &unlocked).unwrap();
        let fresh_row = Zeroizing::new(AccountRow {
            member_id: fresh.member_id,
            username: fresh.username.clone(),
            identity_pub: fresh.identity_pub,
            signing_pub: fresh.signing_pub,
            wrapped_secret_keys: fresh.wrapped_secret_keys.into(),
            kdf_salt: fresh.kdf_salt,
            kdf_mem_kib: fresh.kdf_mem_kib,
            kdf_iters: fresh.kdf_iters,
            kdf_parallelism: fresh.kdf_parallelism,
        });
        let fresh_unlock = unlock_offline(Zeroizing::new(password.clone()), fresh_row).unwrap();
        assert_eq!(fresh_unlock.identity_secret, unlocked.identity_secret);
        assert_eq!(fresh_unlock.signing_seed, unlocked.signing_seed);
        assert_eq!(fresh_unlock.member_id, member_id);

        // ── offline unlock recovers the same secrets ──
        let row = Zeroizing::new(AccountRow {
            member_id: account.member_id,
            username: account.username.clone(),
            identity_pub: account.identity_pub,
            signing_pub: account.signing_pub,
            wrapped_secret_keys: account.wrapped_secret_keys.into(),
            kdf_salt: account.kdf_salt,
            kdf_mem_kib: account.kdf_mem_kib,
            kdf_iters: account.kdf_iters,
            kdf_parallelism: account.kdf_parallelism,
        });
        let offline = unlock_offline(Zeroizing::new(password), row.clone()).unwrap();
        assert_eq!(offline.identity_secret, unlocked.identity_secret);
        assert_eq!(offline.signing_seed, unlocked.signing_seed);

        // Wrong password must fail to unlock offline.
        assert!(unlock_offline(Zeroizing::new("wrong password".to_string()), row).is_err());
    }

    /// Seal the unlocked keys to a freshly generated age key, recover them from
    /// the cache, and confirm the bundled device-auth key signs a challenge that
    /// verifies against its enrolled public key (the server's check).
    #[test]
    fn device_cache_round_trip_and_challenge() {
        use secrecy::ExposeSecret;

        let keys = UnlockedKeys {
            member_id: MemberId([5u8; 16]),
            identity_secret: [9u8; 32],
            identity_pub: X25519Pub([1u8; 32]),
            signing_seed: [7u8; 32],
            signing_pub: Ed25519Pub([2u8; 32]),
            token: "live-token-should-not-be-cached".into(),
        };

        // A throwaway local age key plays the role of the user's AGE identity.
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let identity_str = identity.to_string().expose_secret().to_string();

        let (device_id, device_seed, device_pub) = generate_device_identity();
        let blob = build_device_cache(
            crypto::DeviceBackend::Age,
            &recipient,
            &keys,
            device_id,
            device_seed,
            device_pub,
        )
        .unwrap();

        // The sealed blob must not be the plaintext, and must not leak the token.
        assert!(!blob.windows(9).any(|w| w == b"live-toke"));

        let recovered =
            unlock_from_device_cache(crypto::DeviceBackend::Age, &identity_str, &blob).unwrap();
        assert_eq!(recovered.keys.identity_secret, keys.identity_secret);
        assert_eq!(recovered.keys.signing_seed, keys.signing_seed);
        assert_eq!(recovered.keys.member_id, keys.member_id);
        assert_eq!(recovered.device_id, device_id);
        assert!(recovered.keys.token.is_empty(), "token must not be cached");

        // The device-auth key signs a challenge that verifies against device_pub,
        // exactly as the server will verify it.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let member_uuid = Uuid::from_bytes(keys.member_id.0);
        let device_uuid = Uuid::from_bytes(device_id);
        let nonce = [42u8; 32];
        let sig = crypto::sign_device_challenge(
            &recovered.device_signing_seed,
            &member_uuid,
            &device_uuid,
            &nonce,
        );
        let vk = VerifyingKey::from_bytes(&recovered.device_signing_pub).unwrap();
        let msg = todoers_types::device_challenge_view(
            todoers_types::DEVICE_CHALLENGE_VERSION,
            &member_uuid,
            &device_uuid,
            &nonce,
        );
        assert!(vk.verify(&msg, &Signature::from_bytes(&sig)).is_ok());

        // A wrong age identity cannot open the cache.
        let other = age::x25519::Identity::generate();
        assert!(
            unlock_from_device_cache(
                crypto::DeviceBackend::Age,
                other.to_string().expose_secret(),
                &blob
            )
            .is_err()
        );
    }

    /// A login attempt with the wrong password must fail at client finish.
    #[test]
    fn wrong_password_fails_login() {
        let mut rng = OsRng;
        let setup = ServerSetup::<SharedCipherSuite>::new(&mut rng);
        let (username, password) = ("bob", "hunter2");

        let (flow, start_req) = register_begin(username, password).unwrap();
        let member_id = MemberId::from_identity_pub(&start_req.identity_pub);
        let server_reg_start = ServerRegistration::start(
            &setup,
            RegistrationRequest::<SharedCipherSuite>::deserialize(&start_req.registration_req)
                .unwrap(),
            member_id.as_bytes(),
        )
        .unwrap();
        let (finish_req, _account) = register_finish(
            flow,
            StartRegisterResponse {
                response: server_reg_start.message.serialize().to_vec(),
            },
        )
        .unwrap();
        let password_file = ServerRegistration::finish(
            RegistrationUpload::<SharedCipherSuite>::deserialize(&finish_req.registration_up)
                .unwrap(),
        );

        // Log in with the WRONG password.
        let (lflow, lstart_req) = login_begin(username, "wrong password").unwrap();
        let server_login_start = ServerLogin::start(
            &mut rng,
            &setup,
            Some(password_file),
            CredentialRequest::<SharedCipherSuite>::deserialize(&lstart_req.credential_req)
                .unwrap(),
            member_id.as_bytes(),
            ServerLoginParameters::default(),
        )
        .unwrap();
        let lstart_resp = LoginStartResponse {
            login_id: Uuid::new_v4(),
            credential_response: server_login_start.message.serialize().to_vec(),
        };
        assert!(login_finish(lflow, lstart_resp).is_err());
    }
}
