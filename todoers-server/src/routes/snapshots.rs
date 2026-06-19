//! HTTP handlers for list snapshots: get and put.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;

use todoers_types::{PutSnapshot, SnapshotDto};

use crate::error::{AppError, AppResult};
use crate::state::AppState;

use super::auth::AuthMember;

/// `GET /v1/lists/{list_id}/snapshot`
pub async fn get_snapshot(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    _auth: AuthMember,
) -> AppResult<Json<SnapshotDto>> {
    state
        .db
        .fetch_snapshot(list_id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

/// `PUT /v1/lists/{list_id}/snapshot` — client-driven compaction. The server
/// stores the new snapshot and deletes superseded updates (in one tx).
pub async fn put_snapshot(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    _auth: AuthMember,
    Json(body): Json<PutSnapshot>,
) -> AppResult<StatusCode> {
    if body.nonce.len() != 24 || body.signature.len() != 64 {
        return Err(AppError::BadRequest("bad nonce/signature length".into()));
    }
    state
        .db
        .upsert_snapshot(
            list_id,
            body.epoch,
            body.covers_seq,
            &body.nonce,
            &body.ciphertext,
            &body.signature,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
