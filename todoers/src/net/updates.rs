//! Data-plane transport: the append-only update log. Append uploads one
//! encrypt-then-signed envelope; pull walks the server's global `seq` after a
//! cursor. The server assigns `seq` and dedups by signature, so re-uploading an
//! already-acked update is harmless.

use anyhow::Context;
use reqwest::Client;
use uuid::Uuid;

use todoers_types::{AppendResult, AppendUpdate, StoredUpdateDto};

/// Append a signed/encrypted update; returns the server-assigned `seq`.
pub async fn append_update(
    base_url: &str,
    token: &str,
    list_id: Uuid,
    body: &AppendUpdate,
) -> anyhow::Result<AppendResult> {
    let base = base_url.trim_end_matches('/');
    let resp: AppendResult = Client::new()
        .post(format!("{base}/v1/lists/{list_id}/updates"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .context("append update request failed")?
        .error_for_status()
        .context("append update rejected by the server")?
        .json()
        .await
        .context("invalid append update response")?;
    Ok(resp)
}

/// Pull up to `limit` updates with `seq > after`, in ascending `seq` order.
pub async fn pull_updates(
    base_url: &str,
    token: &str,
    list_id: Uuid,
    after: i64,
    limit: i64,
) -> anyhow::Result<Vec<StoredUpdateDto>> {
    let base = base_url.trim_end_matches('/');
    let resp: Vec<StoredUpdateDto> = Client::new()
        .get(format!(
            "{base}/v1/lists/{list_id}/updates?after={after}&limit={limit}"
        ))
        .bearer_auth(token)
        .send()
        .await
        .context("pull updates request failed")?
        .error_for_status()
        .context("pull updates rejected by the server")?
        .json()
        .await
        .context("invalid pull updates response")?;
    Ok(resp)
}
