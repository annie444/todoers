//! Data-plane transport: compaction snapshots. A client periodically folds the
//! update log into a single re-encrypted snapshot and `put`s it with a
//! `covers_seq` high-water mark; the server then drops the folded updates.

use reqwest::{Method, StatusCode};
use todoers_types::{ListId, PutSnapshot, SnapshotDto};

use super::{Net, unit};
use crate::error::TodoersResult;

impl Net {
    /// Fetch the latest snapshot, or `None` if the list has never been compacted
    /// (the server answers a fresh list with 404). `list_id` rides in the body.
    ///
    /// Special-cased rather than using [`super::decode`]: the 404 must be inspected
    /// *before* `error_for_status` turns it into an error.
    #[tracing::instrument(skip(self, token))]
    pub async fn get_snapshot(
        &self,
        token: &str,
        id: &ListId,
    ) -> TodoersResult<Option<SnapshotDto>> {
        let resp = self
            .req(Method::PUT, "lists/snapshot", Some(token))
            .body(postcard::to_stdvec(id)?)
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let bytes = resp.error_for_status()?.bytes().await?;
        Ok(Some(postcard::from_bytes(&bytes)?))
    }

    /// Upload a re-encrypted compaction snapshot; the server deletes superseded
    /// updates (`seq <= covers_seq`) in the same transaction. `body` carries the
    /// `list_id`.
    #[tracing::instrument(skip(self, token, body))]
    pub async fn put_snapshot(&self, token: &str, body: &PutSnapshot) -> TodoersResult<()> {
        unit(
            self.req(Method::POST, "lists/snapshot", Some(token))
                .body(postcard::to_stdvec(body)?),
        )
        .await
    }
}
