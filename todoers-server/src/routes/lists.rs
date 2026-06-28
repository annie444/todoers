//! HTTP handlers for the data and control plane.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;

use todoers_types::{
    AddMemberRequest, CreateListRequest, ListId, MemberId, MetadataResponse, RemoveMemberRequest,
    Role,
};

use crate::error::{AppError, AppResult};
use crate::state::AppState;

use super::auth::AuthMember;

pub async fn create_list(
    State(state): State<AppState>,
    auth: AuthMember,
    bytes: Bytes,
) -> AppResult<(StatusCode, Bytes)> {
    let body: CreateListRequest = postcard::from_bytes(&bytes)?;
    let list_id = body.list_id;
    state
        .db
        .create_list(&list_id, &auth.member_id, &body.wrapped_dek)
        .await?;
    let out = postcard::to_stdvec(&list_id)?;
    Ok((StatusCode::CREATED, Bytes::from(out)))
}

pub async fn fetch_lists(State(state): State<AppState>, auth: AuthMember) -> AppResult<Bytes> {
    let list_ids = state.db.fetch_user_lists(&auth.member_id).await?;
    let out = postcard::to_stdvec(&list_ids)?;
    Ok(Bytes::from(out))
}

pub async fn delete_list(
    State(state): State<AppState>,
    auth: AuthMember,
    bytes: Bytes,
) -> AppResult<StatusCode> {
    let list_id: ListId = postcard::from_bytes(&bytes)?;
    require_owner(&state, &list_id, &auth.member_id).await?;
    state.db.delete_list(&list_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_member(
    State(state): State<AppState>,
    auth: AuthMember,
    bytes: Bytes,
) -> AppResult<StatusCode> {
    let req: AddMemberRequest = postcard::from_bytes(&bytes)?;
    require_owner(&state, &req.list_id, &auth.member_id).await?;
    if req.role != Role::Owner && req.role != Role::Member {
        return Err(AppError::BadRequest("invalid role".into()));
    }
    state
        .db
        .add_member(
            &req.list_id,
            &req.member_id,
            req.role,
            req.epoch,
            &req.wrapped_dek,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_member(
    State(state): State<AppState>,
    auth: AuthMember,
    bytes: Bytes,
) -> AppResult<StatusCode> {
    let req: RemoveMemberRequest = postcard::from_bytes(&bytes)?;
    require_owner(&state, &req.list_id, &auth.member_id).await?;
    state
        .db
        .remove_member(
            &req.list_id,
            &req.remove_member_id,
            req.epoch,
            &req.new_slots,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Reject callers that are not an `Owner` of `list_id` (membership control is an
/// owner-only operation). Non-members and plain members get a 403.
async fn require_owner(state: &AppState, list_id: &ListId, member_id: &MemberId) -> AppResult<()> {
    match state.db.member_role(list_id, member_id).await? {
        Some(Role::Owner) => Ok(()),
        _ => Err(AppError::Forbidden(
            "only an owner may change membership".into(),
        )),
    }
}

pub async fn get_metadata(
    State(state): State<AppState>,
    _auth: AuthMember,
    bytes: Bytes,
) -> AppResult<Bytes> {
    let list_id: ListId = postcard::from_bytes(&bytes)?;
    let current_epoch = state.db.list_current_epoch(&list_id).await?;
    let members = state.db.fetch_members(&list_id).await?;
    let snapshot = state.db.fetch_snapshot(&list_id).await?;
    let out = postcard::to_stdvec(&MetadataResponse {
        list_id,
        current_epoch,
        snapshot,
        members,
    })?;
    Ok(Bytes::from(out))
}

/// The caller's own wrapped DEKs for a list (one per live epoch).
pub async fn get_my_keys(
    State(state): State<AppState>,
    auth: AuthMember,
    bytes: Bytes,
) -> AppResult<Bytes> {
    let list_id: ListId = postcard::from_bytes(&bytes)?;
    let slots = state
        .db
        .fetch_my_key_slots(&list_id, &auth.member_id)
        .await?;
    let out = postcard::to_stdvec(&slots)?;
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{StatusCode, header::AUTHORIZATION};
    use axum_test::TestServer;
    use old_rand_core::OsRng;

    use crate::routes::testutil::register_and_login;

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_create_list_requires_auth(db: sqlx::PgPool) {
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        let mut rng = OsRng;
        let body = postcard::to_stdvec(&CreateListRequest {
            list_id: ListId::generate(&mut rng),
            wrapped_dek: vec![],
        })
        .unwrap();
        // `AuthMember` runs before the body extractor, so a missing token is 401.
        let resp = server.post("/v1/lists").bytes(body.into()).await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn test_create_list_authed(db: sqlx::PgPool) {
        let state = AppState::new_for_test(db);
        let server = TestServer::new(crate::routes::build_router(state).await);
        let token = register_and_login(&server, "carol", "pw").await;
        let mut rng = OsRng;
        let body = postcard::to_stdvec(&CreateListRequest {
            list_id: ListId::generate(&mut rng),
            wrapped_dek: vec![],
        })
        .unwrap();
        let resp = server
            .post("/v1/lists")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .bytes(body.into())
            .await;
        resp.assert_status(StatusCode::CREATED);

        let resp_body: ListId = postcard::from_bytes(resp.as_bytes()).unwrap();

        let resp = server
            .get("/v1/lists")
            .add_header(AUTHORIZATION, format!("Bearer {token}"))
            .await;
        resp.assert_status(StatusCode::OK);

        let list_ids: Vec<ListId> = postcard::from_bytes(resp.as_bytes()).unwrap();

        assert_eq!(resp_body, list_ids[0]);
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

        let mut rng = OsRng;
        let body = postcard::to_stdvec(&CreateListRequest {
            list_id: ListId::generate(&mut rng),
            wrapped_dek: vec![],
        })
        .unwrap();

        // Carol creates a list, becoming its owner.
        let resp = server
            .post("/v1/lists")
            .add_header(AUTHORIZATION, format!("Bearer {carol}"))
            .bytes(body.into())
            .await;
        resp.assert_status(StatusCode::CREATED);
        let list_id: ListId = postcard::from_bytes(resp.as_bytes()).unwrap();

        // The member being added must be a real registered user (FK).
        let resp_dave = server
            .put("/v1/users/pubkeys")
            .add_header(AUTHORIZATION, format!("Bearer {carol}"))
            .bytes(postcard::to_stdvec(&"dave".to_string()).unwrap().into())
            .await;

        let ret: todoers_types::UserPubkeysDto =
            postcard::from_bytes(resp_dave.as_bytes()).unwrap();

        let dave_id = ret.member_id;

        let body = AddMemberRequest {
            list_id,
            member_id: dave_id,
            role: Role::Member,
            wrapped_dek: [1u8; 32].to_vec(),
            epoch: 1,
        };

        let bytes = postcard::to_stdvec(&body).unwrap();

        // Dave is not a member at all → forbidden.
        let resp = server
            .post("/v1/lists/members")
            .add_header(AUTHORIZATION, format!("Bearer {dave}"))
            .bytes(Bytes::from(bytes.clone()))
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);

        // Carol, the owner, may add members.
        let resp = server
            .post("/v1/lists/members")
            .add_header(AUTHORIZATION, format!("Bearer {carol}"))
            .bytes(Bytes::from(bytes))
            .await;
        resp.assert_status(StatusCode::NO_CONTENT);
    }
}
