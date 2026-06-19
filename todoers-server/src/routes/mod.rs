use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::response::Response;
use axum::routing::{any, get, post};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::Span;

use crate::state::AppState;

mod auth;
mod health;
mod lists;
mod snapshots;
#[cfg(test)]
pub(crate) mod testutil;
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
        .route("/v1/auth/logout", post(auth::logout))
        .layer(
            ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(|request: &Request<Body>| {
                            tracing::info_span!(
                                "http_request",
                                method = %request.method(),
                                uri = %request.uri(),
                                status_code = tracing::field::Empty,
                            )
                        })
                        .on_response(
                            |response: &Response<Body>, latency: std::time::Duration, span: &Span| {
                                span.record("status_code", response.status().as_u16());
                                tracing::info!(parent: span, latency_ms = latency.as_millis(), "response");
                            },
                        ),
                )
        )
        .with_state(state)
}
