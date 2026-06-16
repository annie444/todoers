use axum::Router;
use axum::routing::{any, get, post};

use crate::state::AppState;

mod auth;
mod health;
mod lists;
mod snapshots;
mod updates;
mod users;
mod ws;

pub async fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        // control plane
        .route("/v1/lists", post(lists::create_list))
        .route("/v1/lists/{list_id}", get(lists::get_metadata))
        .route(
            "/v1/lists/{list_id}/members",
            post(lists::add_member).delete(lists::remove_member),
        )
        .route("/v1/lists/{list_id}/keys", get(lists::get_my_keys))
        .route("/v1/users/{username}/pubkeys", get(users::get_user_pubkeys))
        // data plane
        .route(
            "/v1/lists/{list_id}/updates",
            post(updates::append_update).get(updates::pull_updates),
        )
        .route(
            "/v1/lists/{list_id}/snapshot",
            get(snapshots::get_snapshot).put(snapshots::put_snapshot),
        )
        // real-time (any() so the upgrade works over HTTP/1.1 and HTTP/2)
        .route("/v1/lists/{list_id}/ws", any(ws::ws_handler))
        // auth (OPAQUE: each flow is two messages)
        .route("/v1/auth/register/start", post(auth::registration_start))
        .route("/v1/auth/register/finish", post(auth::registration_finish))
        .route("/v1/auth/login/start", post(auth::login_start))
        .route("/v1/auth/login/finish", post(auth::login_finish))
        .with_state(state)
}
