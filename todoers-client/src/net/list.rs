//! Control-plane transport: lists, members, and per-list key slots. All calls
//! are authenticated with the session bearer `token`; the server stores only the
//! opaque ciphertext / wrapped keys these carry.

use reqwest::Method;
use todoers_types::{
    AddMemberRequest, CreateListRequest, KeySlotDto, ListId, MetadataResponse, RemoveMemberRequest,
};

use super::{Net, decode, unit};
use crate::error::TodoersResult;

impl Net {
    /// Create a server-side list seated to the caller under the client-minted
    /// `list_id`, uploading our own wrapped DEK for epoch 1. The server adopts the
    /// id (so an offline-created list keeps a stable id) and echoes it back.
    #[tracing::instrument(skip(self, token, wrapped_dek))]
    pub async fn create_list(
        &self,
        token: &str,
        id: &ListId,
        wrapped_dek: &[u8],
    ) -> TodoersResult<ListId> {
        // `wrapped_dek` is a sealed box (`crypto::seal_to`), ~80 bytes — NOT a raw
        // 32-byte DEK. Send it verbatim; the server stores it opaquely as our epoch-1
        // key slot and echoes it back via `get_my_keys`.
        let req = CreateListRequest {
            list_id: *id,
            wrapped_dek: wrapped_dek.to_vec(),
        };
        decode(
            self.req(Method::POST, "lists", Some(token))
                .body(postcard::to_stdvec(&req)?),
        )
        .await
    }

    #[tracing::instrument(skip(self, token))]
    pub async fn delete_list(&self, token: &str, id: &ListId) -> TodoersResult<()> {
        unit(
            self.req(Method::DELETE, "lists", Some(token))
                .body(postcard::to_stdvec(id)?),
        )
        .await
    }

    /// The ids of every list the caller is a member of.
    #[tracing::instrument(skip(self, token))]
    pub async fn fetch_lists(&self, token: &str) -> TodoersResult<Vec<ListId>> {
        decode(self.req(Method::GET, "lists", Some(token))).await
    }

    /// Full server-side metadata for a list: current epoch, members, latest snapshot.
    #[tracing::instrument(skip(self, token))]
    pub async fn get_metadata(&self, token: &str, id: &ListId) -> TodoersResult<MetadataResponse> {
        decode(
            self.req(Method::PUT, "lists/metadata", Some(token))
                .body(postcard::to_stdvec(id)?),
        )
        .await
    }

    /// Seat a new member, uploading the current DEK sealed to their identity_pub.
    /// Owner-only on the server. (`body` already carries the `list_id`.)
    #[tracing::instrument(skip(self, token, body))]
    pub async fn add_member(&self, token: &str, body: &AddMemberRequest) -> TodoersResult<()> {
        unit(
            self.req(Method::POST, "lists/members", Some(token))
                .body(postcard::to_stdvec(body)?),
        )
        .await
    }

    /// Remove a member and rotate: the body carries the fresh DEK sealed per
    /// remaining member. Owner-only on the server. (`body` carries the `list_id`.)
    #[tracing::instrument(skip(self, token, body))]
    pub async fn remove_member(
        &self,
        token: &str,
        body: &RemoveMemberRequest,
    ) -> TodoersResult<()> {
        unit(
            self.req(Method::DELETE, "lists/members", Some(token))
                .body(postcard::to_stdvec(body)?),
        )
        .await
    }

    /// The caller's own wrapped DEKs across all live epochs for a list — used to
    /// rehydrate DEKs a fresh device has never seen (e.g. after being added).
    #[tracing::instrument(skip(self, token))]
    pub async fn get_my_keys(&self, token: &str, id: &ListId) -> TodoersResult<Vec<KeySlotDto>> {
        decode(
            self.req(Method::PUT, "lists/keys", Some(token))
                .body(postcard::to_stdvec(id)?),
        )
        .await
    }
}
