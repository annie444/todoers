//! HTTP handlers for list snapshots: get and put.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;

use todoers_types::{ListId, PutSnapshot};

use crate::error::{AppError, AppResult};
use crate::state::AppState;

use super::auth::AuthMember;

/// `PUT /v1/lists/snapshot` — read a list's latest snapshot (`list_id` in body).
pub async fn get_snapshot(
    State(state): State<AppState>,
    _auth: AuthMember,
    bytes: Bytes,
) -> AppResult<Bytes> {
    let list_id: ListId = postcard::from_bytes(&bytes)?;
    let snapshot = state
        .db
        .fetch_snapshot(&list_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Bytes::from(postcard::to_stdvec(&snapshot)?))
}

/// `POST /v1/lists/snapshot` — client-driven compaction (`list_id` in body). The
/// server stores the new snapshot and deletes superseded updates (in one tx).
pub async fn put_snapshot(
    State(state): State<AppState>,
    _auth: AuthMember,
    bytes: Bytes,
) -> AppResult<StatusCode> {
    let body: PutSnapshot = postcard::from_bytes(&bytes)?;
    if body.nonce.len() != 24 || body.signature.len() != 64 {
        return Err(AppError::BadRequest("bad nonce/signature length".into()));
    }
    state
        .db
        .upsert_snapshot(
            &body.list_id,
            body.epoch,
            body.covers_seq,
            &body.nonce,
            &body.ciphertext,
            &body.signature,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
