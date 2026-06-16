//! HTTP handlers for the data and control plane.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::wire::{AddMemberRequest, KeySlotDto, MetadataResponse, RemoveMemberRequest, Role, b64};

use super::auth::AuthMember;

#[derive(serde::Deserialize)]
pub struct CreateListRequest {
    #[serde(with = "b64")]
    pub wrapped_dek: Vec<u8>,
}

#[derive(serde::Serialize)]
pub struct CreateListResponse {
    pub list_id: Uuid,
}

pub async fn create_list(
    State(state): State<AppState>,
    auth: AuthMember,
    Json(body): Json<CreateListRequest>,
) -> AppResult<(StatusCode, Json<CreateListResponse>)> {
    let list_id = Uuid::new_v4();
    state
        .db
        .create_list(list_id, auth.0, &body.wrapped_dek)
        .await?;
    Ok((StatusCode::CREATED, Json(CreateListResponse { list_id })))
}

pub async fn add_member(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    _auth: AuthMember, // TODO: require owner role
    Json(body): Json<AddMemberRequest>,
) -> AppResult<StatusCode> {
    if body.role != Role::Owner && body.role != Role::Member {
        return Err(AppError::BadRequest("invalid role".into()));
    }
    state
        .db
        .add_member(
            list_id,
            body.member_id,
            body.role,
            body.epoch,
            &body.wrapped_dek,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_member(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    _auth: AuthMember, // TODO: require owner role
    Json(body): Json<RemoveMemberRequest>,
) -> AppResult<StatusCode> {
    state
        .db
        .remove_member(
            list_id,
            body.remove_member_id,
            body.epoch,
            &body.wrapped_dek,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_metadata(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    _auth: AuthMember,
) -> AppResult<Json<MetadataResponse>> {
    let current_epoch = state.db.list_current_epoch(list_id).await?;
    let members = state.db.fetch_members(list_id).await?;
    let snapshot = state.db.fetch_snapshot(list_id).await?;
    Ok(Json(MetadataResponse {
        list_id,
        current_epoch,
        snapshot,
        members,
    }))
}

/// The caller's own wrapped DEKs for a list (one per live epoch).
pub async fn get_my_keys(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    auth: AuthMember,
) -> AppResult<Json<Vec<KeySlotDto>>> {
    let slots = state.db.fetch_my_key_slots(list_id, auth.0).await?;
    Ok(Json(slots))
}
