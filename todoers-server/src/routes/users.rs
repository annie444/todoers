//! HTTP handlers for user data

use axum::Json;
use axum::extract::{Path, State};

use todoers_types::UserPubkeysDto;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

use super::auth::AuthMember;

/// Public-key lookup for sharing: resolve a username to identity/signing keys
/// so an owner client can seal a DEK to a new member.
pub async fn get_user_pubkeys(
    State(state): State<AppState>,
    Path(username): Path<String>,
    _auth: AuthMember,
) -> AppResult<Json<UserPubkeysDto>> {
    state
        .db
        .fetch_user_pubkeys(&username)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}



