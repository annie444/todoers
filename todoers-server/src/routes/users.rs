//! HTTP handlers for user data

use axum::body::Bytes;
use axum::extract::State;

use crate::error::{AppError, AppResult};
use crate::state::AppState;

use super::auth::AuthMember;

/// Public-key lookup for sharing: resolve a username (postcard `String` body) to
/// identity/signing keys so an owner client can seal a DEK to a new member.
pub async fn get_user_pubkeys(
    State(state): State<AppState>,
    _auth: AuthMember,
    bytes: Bytes,
) -> AppResult<Bytes> {
    let username: String = postcard::from_bytes(&bytes)?;
    let pubkeys = state
        .db
        .fetch_user_pubkeys(&username)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Bytes::from(postcard::to_stdvec(&pubkeys)?))
}



