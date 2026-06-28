//! Shared test helpers for the route modules. Drives the OPAQUE client side (the
//! server crate already depends on `opaque-ke`) through all four auth endpoints so
//! any endpoint test can obtain a real bearer token in one call.

use axum_test::TestServer;
use old_rand_core::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};

use todoers_types::{
    Ed25519Pub, FinishRegisterRequest, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, SharedCipherSuite, StartRegisterRequest, StartRegisterResponse, X25519Pub,
};

/// Sentinel escrow blob: the server stores/returns it blindly, so tests can assert
/// it round-trips byte-for-byte through register → login.
pub const ESCROW_SENTINEL: &[u8] = b"escrow-secret-keys-blob";

/// Register a brand-new user and log them in, returning the bearer token.
///
/// Uses an X25519 `StaticSecret` so `identity_pub` (and thus the server-derived
/// `member_id`) is stable across the two phases.
pub async fn register_and_login(server: &TestServer, username: &str, password: &str) -> String {
    let mut rng = OsRng;

    let id_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let identity_pub = X25519Pub::new(x25519_dalek::PublicKey::from(&id_secret).to_bytes());
    let signing = ed25519_dalek::SigningKey::generate(&mut rng);

    // ── register/start ──
    let reg_start =
        ClientRegistration::<SharedCipherSuite>::start(&mut rng, password.as_bytes()).unwrap();
    let resp = server
        .post("/v1/auth/register/start")
        .bytes(
            postcard::to_stdvec(&StartRegisterRequest {
                identity_pub: identity_pub.clone(),
                registration_req: reg_start.message.serialize().to_vec(),
            })
            .unwrap()
            .into(),
        )
        .await;
    resp.assert_status_ok();
    let start_resp: StartRegisterResponse = postcard::from_bytes(resp.as_bytes()).unwrap();

    let reg_response =
        RegistrationResponse::<SharedCipherSuite>::deserialize(&start_resp.response).unwrap();
    let reg_finish = reg_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            reg_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    // ── register/finish ──
    let resp = server
        .post("/v1/auth/register/finish")
        .bytes(
            postcard::to_stdvec(&FinishRegisterRequest {
                username: username.to_string(),
                identity_pub,
                signing_pub: Ed25519Pub::new(signing.verifying_key().to_bytes()),
                wrapped_secret_keys: ESCROW_SENTINEL.to_vec(),
                registration_up: reg_finish.message.serialize().to_vec(),
            })
            .unwrap()
            .into(),
        )
        .await;
    resp.assert_status_ok();

    let login_resp = login(server, username, password).await;
    // The escrow blob the server stored must round-trip unchanged.
    assert_eq!(login_resp.wrapped_secret_keys, ESCROW_SENTINEL);
    login_resp.token
}

/// Log in an already-registered user and return the full finish response. Useful
/// for minting a SECOND session of the same user (e.g. to test per-device logout).
pub async fn login(server: &TestServer, username: &str, password: &str) -> LoginFinishResponse {
    let mut rng = OsRng;

    let login_start =
        ClientLogin::<SharedCipherSuite>::start(&mut rng, password.as_bytes()).unwrap();
    let resp = server
        .post("/v1/auth/login/start")
        .bytes(
            postcard::to_stdvec(&LoginStartRequest {
                username: username.to_string(),
                credential_req: login_start.message.serialize().to_vec(),
            })
            .unwrap()
            .into(),
        )
        .await;
    resp.assert_status_ok();
    let login_start_resp: LoginStartResponse = postcard::from_bytes(resp.as_bytes()).unwrap();

    let cred_response =
        CredentialResponse::<SharedCipherSuite>::deserialize(&login_start_resp.credential_response)
            .unwrap();
    let login_finish = login_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            cred_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    let resp = server
        .post("/v1/auth/login/finish")
        .bytes(
            postcard::to_stdvec(&LoginFinishRequest {
                login_id: login_start_resp.login_id,
                credential_finalization: login_finish.message.serialize().to_vec(),
            })
            .unwrap()
            .into(),
        )
        .await;
    resp.assert_status_ok();
    postcard::from_bytes(resp.as_bytes()).unwrap()
}
