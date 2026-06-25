//! Control-plane transport: lists, members, and per-list key slots. All calls
//! are authenticated with the session bearer `token`; the server stores only the
//! opaque ciphertext / wrapped keys these carry.

use reqwest::Client;
use uuid::Uuid;

use todoers_types::{
    AddMemberRequest, CreateListRequest, KeySlotDto, ListIdDto, ListIdsDto, MetadataResponse,
    RemoveMemberRequest,
};

use crate::error::TodoersResult;

/// Create a server-side list seated to the caller under the client-minted
/// `list_id`, uploading our own wrapped DEK for epoch 1. The server adopts the
/// id (so an offline-created list keeps a stable id) and echoes it back.
pub async fn create_list(
    base_url: &str,
    token: &str,
    list_id: Uuid,
    wrapped_dek: &[u8],
) -> TodoersResult<Uuid> {
    let base = base_url.trim_end_matches('/');
    let resp: ListIdDto = Client::new()
        .post(format!("{base}/v1/lists"))
        .bearer_auth(token)
        .json(&CreateListRequest {
            list_id,
            wrapped_dek: wrapped_dek.to_vec(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp.list_id)
}

/// The ids of every list the caller is a member of.
pub async fn fetch_lists(base_url: &str, token: &str) -> TodoersResult<ListIdsDto> {
    let base = base_url.trim_end_matches('/');
    let lists: ListIdsDto = Client::new()
        .get(format!("{base}/v1/lists"))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(lists)
}

/// Full server-side metadata for a list: current epoch, members, latest snapshot.
pub async fn get_metadata(
    base_url: &str,
    token: &str,
    list_id: Uuid,
) -> TodoersResult<MetadataResponse> {
    let base = base_url.trim_end_matches('/');
    let resp: MetadataResponse = Client::new()
        .get(format!("{base}/v1/lists/{list_id}"))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp)
}

/// Seat a new member, uploading the current DEK sealed to their identity_pub.
/// Owner-only on the server.
pub async fn add_member(
    base_url: &str,
    token: &str,
    list_id: Uuid,
    body: &AddMemberRequest,
) -> TodoersResult<()> {
    let base = base_url.trim_end_matches('/');
    Client::new()
        .post(format!("{base}/v1/lists/{list_id}/members"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Remove a member and rotate: the body carries the fresh DEK sealed per
/// remaining member. Owner-only on the server.
pub async fn remove_member(
    base_url: &str,
    token: &str,
    list_id: Uuid,
    body: &RemoveMemberRequest,
) -> TodoersResult<()> {
    let base = base_url.trim_end_matches('/');
    Client::new()
        .delete(format!("{base}/v1/lists/{list_id}/members"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// The caller's own wrapped DEKs across all live epochs for a list — used to
/// rehydrate DEKs a fresh device has never seen (e.g. after being added).
pub async fn get_my_keys(
    base_url: &str,
    token: &str,
    list_id: Uuid,
) -> TodoersResult<Vec<KeySlotDto>> {
    let base = base_url.trim_end_matches('/');
    let resp: Vec<KeySlotDto> = Client::new()
        .get(format!("{base}/v1/lists/{list_id}/keys"))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp)
}
