//! Data-plane transport: the append-only update log. Append uploads one
//! encrypt-then-signed envelope; pull walks the server's global `seq` after a
//! cursor. The server assigns `seq` and dedups by signature, so re-uploading an
//! already-acked update is harmless.

use reqwest::Method;
use todoers_types::{AppendResult, AppendUpdate, ListId, PullParams, StoredUpdateDto};

use super::{Net, decode};
use crate::error::TodoersResult;

impl Net {
    /// Append a signed/encrypted update; returns the server-assigned `seq`.
    /// `body` already carries the `list_id`.
    #[tracing::instrument(skip(self, token, body))]
    pub async fn append_update(
        &self,
        token: &str,
        body: &AppendUpdate,
    ) -> TodoersResult<AppendResult> {
        decode(
            self.req(Method::POST, "lists/updates", Some(token))
                .body(postcard::to_stdvec(body)?),
        )
        .await
    }

    /// Pull up to `limit` updates with `seq > after`, in ascending `seq` order.
    #[tracing::instrument(skip(self, token))]
    pub async fn pull_updates(
        &self,
        token: &str,
        id: &ListId,
        after: i64,
        limit: i64,
    ) -> TodoersResult<Vec<StoredUpdateDto>> {
        let params = PullParams {
            list_id: *id,
            after,
            limit,
        };
        decode(
            self.req(Method::PUT, "lists/updates", Some(token))
                .body(postcard::to_stdvec(&params)?),
        )
        .await
    }
}
