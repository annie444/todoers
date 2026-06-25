//! HTTP handlers for list updates: append and pull.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use uuid::Uuid;

use todoers_types::{AppendResult, AppendUpdate, PullParams, StoredUpdateDto};

use crate::error::{AppError, AppResult};
use crate::state::AppState;

use super::auth::AuthMember;

/// `POST /v1/lists/{list_id}/updates` — append one signed, encrypted update.
pub async fn append_update(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    auth: AuthMember,
    Json(body): Json<AppendUpdate>,
) -> AppResult<(StatusCode, Json<AppendResult>)> {
    // Basic shape checks the JSON layer can't enforce.
    if body.nonce.len() != 24 {
        return Err(AppError::BadRequest("nonce must be 24 bytes".into()));
    }
    if body.signature.len() != 64 {
        return Err(AppError::BadRequest("signature must be 64 bytes".into()));
    }
    // The caller may only write as themselves.
    if body.author != auth.member_id {
        return Err(AppError::Unauthorized);
    }

    // Optional: the one thing a blind server may verify. The author's signing
    // key is fetched from membership, so a non-member has no key → rejected.
    if state.verify_signatures {
        let signing_pub = state
            .db
            .fetch_author_signing_pub(list_id, body.author)
            .await?
            .ok_or(AppError::InvalidSignature)?;

        verify_update_signature(&signing_pub, &body, &list_id)?;
    }

    let seq = state
        .db
        .insert_update(
            list_id,
            body.epoch,
            body.author,
            &body.nonce,
            &body.ciphertext,
            &body.signature,
        )
        .await?;

    // Fan out to online members. We re-serialize the stored shape so WS and
    // pull deliver identical bytes.
    let stored = StoredUpdateDto {
        seq,
        epoch: body.epoch,
        author: body.author,
        nonce: body.nonce,
        ciphertext: body.ciphertext,
        signature: body.signature,
    };
    if let Ok(json) = serde_json::to_vec(&stored) {
        state.hub.publish(
            list_id,
            axum::extract::ws::Message::Binary(Bytes::from(json)),
        );
    }

    Ok((StatusCode::CREATED, Json(AppendResult { seq })))
}

fn verify_update_signature(
    signing_pub: &[u8],
    body: &AppendUpdate,
    list_id: &Uuid,
) -> AppResult<()> {
    let vk_bytes: [u8; 32] = signing_pub
        .try_into()
        .map_err(|_| AppError::InvalidSignature)?;
    let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| AppError::InvalidSignature)?;

    let sig_bytes: [u8; 64] = body
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| AppError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);

    let view = todoers_types::signing_view(
        body.version,
        list_id,
        body.epoch,
        &body.author,
        &body.nonce,
        &body.ciphertext,
    );

    vk.verify(&view, &sig)
        .map_err(|_| AppError::InvalidSignature)
}

/// `GET /v1/lists/{list_id}/updates?after=N&limit=M`
pub async fn pull_updates(
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    _auth: AuthMember,
    Query(params): Query<PullParams>,
) -> AppResult<Json<Vec<StoredUpdateDto>>> {
    let rows = state
        .db
        .fetch_updates_after(list_id, params.after, params.limit)
        .await?;
    Ok(Json(rows))
}
