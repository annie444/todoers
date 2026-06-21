//! HTTP handlers for the data and control plane.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;

use todoers_types::{
    AddMemberRequest, CreateListRequest, KeySlotDto, ListIdDto, ListIdsDto, MetadataResponse,
    RemoveMemberRequest, Role,
};

use crate::error::{AppError, AppResult};
use crate::state::AppState;

use super::auth::AuthMember;

pub async fn create_list(
    State(state): State<AppState>,
    auth: AuthMember,
    Json(body): Json<CreateListRequest>,
) -> AppResult<(StatusCode, Json<ListIdDto>)> {
    let list_id = body.list_id;
    state
        .db
        .create_list(list_id, auth.member_id, &body.wrapped_dek)
        .await?;
    Ok((StatusCode::CREATED, Json(ListIdDto { list_id })))
}

pub async fn fetch_lists(
    State(state): State<AppState>,
    auth: AuthMember,
) -> AppResult<Json<ListIdsDto>> {
    let list_ids = state.db.fetch_user_lists(auth.member_id).await?;
    Ok(Json(ListIdsDto { list_ids }))
}

pub async fn add_member(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    auth: AuthMember,
    Json(body): Json<AddMemberRequest>,
) -> AppResult<StatusCode> {
    require_owner(&state, list_id, auth.member_id).await?;
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
    auth: AuthMember,
    Json(body): Json<RemoveMemberRequest>,
) -> AppResult<StatusCode> {
    require_owner(&state, list_id, auth.member_id).await?;
    state
        .db
        .remove_member(list_id, body.remove_member_id, body.epoch, &body.new_slots)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reject callers that are not an `Owner` of `list_id` (membership control is an
/// owner-only operation). Non-members and plain members get a 403.
async fn require_owner(state: &AppState, list_id: Uuid, member_id: Uuid) -> AppResult<()> {
    match state.db.member_role(list_id, member_id).await? {
        Some(Role::Owner) => Ok(()),
        _ => Err(AppError::Forbidden(
            "only an owner may change membership".into(),
        )),
    }
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
    let slots = state.db.fetch_my_key_slots(list_id, auth.member_id).await?;
    Ok(Json(slots))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, header::AUTHORIZATION};
    use axum_test::TestServer;

    use crate::routes::testutil::register_and_login;

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_create_list_requires_auth(db: sqlx::PgPool) {
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        // `AuthMember` runs before the body extractor, so a missing token is 401.
        let resp = server
            .post("/v1/lists")
            .json(&serde_json::json!({ "list_id": Uuid::new_v4(), "wrapped_dek": "AAAA" }))
            .await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_create_list_authed(db: sqlx::PgPool) {
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        let token = register_and_login(&server, "carol", "pw").await;

        let resp = server
            .post("/v1/lists")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .json(&serde_json::json!({ "list_id": Uuid::new_v4(), "wrapped_dek": "AAAA" }))
            .await;
        resp.assert_status(StatusCode::CREATED);

        let resp_body: ListIdDto = resp.json();

        let resp = server
            .get("/v1/lists")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .await;
        resp.assert_status(StatusCode::OK);

        let list_ids: ListIdsDto = resp.json();

        assert_eq!(resp_body.list_id, list_ids.list_ids[0]);
    }

    /// Membership changes are owner-only: a non-member is forbidden, the owner
    /// is allowed. This also covers the `member_role` gate the WS handler shares.
    #[sqlx::test(migrations = "db/migrations")]
    async fn add_member_requires_owner(db: sqlx::PgPool) {
        use todoers_types::AddMemberRequest;

        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        let carol = register_and_login(&server, "carol", "pw").await;
        let dave = register_and_login(&server, "dave", "pw").await;

        // Carol creates a list, becoming its owner.
        let resp = server
            .post("/v1/lists")
            .add_header(AUTHORIZATION, format!("Bearer {carol}"))
            .json(&serde_json::json!({ "list_id": Uuid::new_v4(), "wrapped_dek": "AAAA" }))
            .await;
        resp.assert_status(StatusCode::CREATED);
        let list_id = resp.json::<ListIdDto>().list_id;

        // The member being added must be a real registered user (FK).
        let dave_id = server
            .get("/v1/users/dave/pubkeys")
            .add_header(AUTHORIZATION, format!("Bearer {carol}"))
            .await
            .json::<todoers_types::UserPubkeysDto>()
            .member_id;

        let body = AddMemberRequest {
            member_id: dave_id,
            role: Role::Member,
            wrapped_dek: vec![1, 2, 3, 4],
            epoch: 1,
        };

        // Dave is not a member at all → forbidden.
        let resp = server
            .post(&format!("/v1/lists/{list_id}/members"))
            .add_header(AUTHORIZATION, format!("Bearer {dave}"))
            .json(&body)
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);

        // Carol, the owner, may add members.
        let resp = server
            .post(&format!("/v1/lists/{list_id}/members"))
            .add_header(AUTHORIZATION, format!("Bearer {carol}"))
            .json(&body)
            .await;
        resp.assert_status(StatusCode::NO_CONTENT);
    }
}
