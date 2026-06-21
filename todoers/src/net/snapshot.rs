//! Data-plane transport: compaction snapshots. A client periodically folds the
//! update log into a single re-encrypted snapshot and `put`s it with a
//! `covers_seq` high-water mark; the server then drops the folded updates.

use anyhow::Context;
use reqwest::Client;
use uuid::Uuid;

use todoers_types::{PutSnapshot, SnapshotDto};

/// Fetch the latest snapshot, or `None` if the list has never been compacted
/// (the server answers a fresh list with 404).
pub async fn get_snapshot(
    base_url: &str,
    token: &str,
    list_id: Uuid,
) -> anyhow::Result<Option<SnapshotDto>> {
    let base = base_url.trim_end_matches('/');
    let resp = Client::new()
        .get(format!("{base}/v1/lists/{list_id}/snapshot"))
        .bearer_auth(token)
        .send()
        .await
        .context("get snapshot request failed")?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let snap: SnapshotDto = resp
        .error_for_status()
        .context("get snapshot rejected by the server")?
        .json()
        .await
        .context("invalid snapshot response")?;
    Ok(Some(snap))
}

/// Upload a re-encrypted compaction snapshot; the server deletes superseded
/// updates (`seq <= covers_seq`) in the same transaction.
pub async fn put_snapshot(
    base_url: &str,
    token: &str,
    list_id: Uuid,
    body: &PutSnapshot,
) -> anyhow::Result<()> {
    let base = base_url.trim_end_matches('/');
    Client::new()
        .put(format!("{base}/v1/lists/{list_id}/snapshot"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .context("put snapshot request failed")?
        .error_for_status()
        .context("put snapshot rejected by the server")?;
    Ok(())
}
