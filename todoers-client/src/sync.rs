//! # Sync engine
//!
//! > The one task that talks to the server over time.
//!
//! It is deliberately key-free. The store actor ([`crate::store_worker`]) owns
//! the DEKs and Loro docs and does every crypto step; this task only moves
//! already-encrypted bytes over the wire and hands raw server DTOs back to the
//! store for keyed work. That split keeps network latency off the store actor
//! (so UI-driven edits never wait on a socket) and keeps secret material out of
//! the component that holds a bearer token.
//!
//! ## Flow:
//! - **Push** drains the local `outbound` queue (pre-signed envelopes) to the
//!   append endpoint, acking each row the server accepts.
//! - **Pull** walks the server log after our cursor and forwards batches to the
//!   store, which decrypts/merges and advances `applied_through_seq`.
//! - **Subscribe** holds a WebSocket for live fanout; on drop it falls back to a
//!   pull, matching the server's "laggards reconcile via pull" contract.
//! - **Control-plane** (create list, add/remove member) ships request bodies the
//!   store pre-built with sealed DEKs.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, error, info, warn};

use todoers_types::{AddMemberRequest, AppendUpdate, ListId, RemoveMemberRequest, UpdatePayload};

use crate::db::Db;
use crate::error::TodoersResult;
use crate::net::{Net, ws};
use crate::worker::{CommandTx, StoreCommand};

/// How many updates to pull/push per round-trip.
const BATCH: i64 = 500;

/// What the UI / store asks the sync engine to do.
#[derive(Debug)]
pub enum SyncCommand {
    /// Local edits for this list were enqueued — drain & upload them.
    Push(ListId),
    /// Create the list server-side under the client-minted id (local-first).
    CreateList {
        list_id: ListId,
        wrapped_dek: Vec<u8>,
    },
    /// Delete the list server-side (local-first).
    DeleteList(ListId),
    /// Seat a new member (body carries the current DEK sealed to them).
    AddMember {
        list_id: ListId,
        body: Box<AddMemberRequest>,
    },
    /// Remove a member (body carries the rotated DEK sealed per remaining member).
    RemoveMember {
        list_id: ListId,
        body: Box<RemoveMemberRequest>,
    },
    /// Discover lists from the server and pull/subscribe each (run after unlock).
    InitialSync,
    /// Pull updates after the local cursor for one list.
    Pull(ListId),
    /// Open a live WebSocket subscription for one list.
    Subscribe(ListId),
}

pub type SyncTx = UnboundedSender<SyncCommand>;
pub type SyncRx = UnboundedReceiver<SyncCommand>;

pub struct SyncEngine {
    net: Net,
    token: String,
    db: Arc<Db>,
    store_tx: CommandTx,
    tx: SyncTx,
    rx: SyncRx,
}

impl SyncEngine {
    #[tracing::instrument(skip(token, db, store_tx, tx, rx))]
    pub fn new(
        base_url: impl Into<String> + std::fmt::Debug,
        token: impl Into<String>,
        db: Arc<Db>,
        store_tx: CommandTx,
        tx: SyncTx,
        rx: SyncRx,
    ) -> TodoersResult<Self> {
        let net = Net::new(base_url.into())?;
        let engine = Self {
            net,
            token: token.into(),
            db,
            store_tx,
            tx,
            rx,
        };
        Ok(engine)
    }

    /// Run the sync engine until its command channel closes. `self_tx` lets a
    /// command enqueue follow-ups (e.g. InitialSync → Pull/Subscribe per list).
    #[tracing::instrument(skip(self))]
    pub async fn run_sync(&mut self) -> TodoersResult<()> {
        info!("Sync engine started");
        // Kick discovery ourselves so the UI layer never speaks SyncCommand.
        // `initial_sync` enqueues Pull/Subscribe via `self.tx`; the loop drains them.
        if let Err(e) = self.handle(SyncCommand::InitialSync).await {
            error!(error = ?e, "initial sync failed");
        }
        while let Some(cmd) = self.rx.recv().await {
            if let Err(e) = self.handle(cmd).await {
                error!(error = ?e, "sync command failed");
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle(&self, cmd: SyncCommand) -> TodoersResult<()> {
        debug!(?cmd, "handling sync command");
        match cmd {
            SyncCommand::Push(list_id) => self.push(list_id).await,
            SyncCommand::CreateList {
                list_id,
                wrapped_dek,
            } => {
                self.net
                    .create_list(&self.token, &list_id, &wrapped_dek)
                    .await?;
                // A freshly-created list has nothing to pull, but go live for peers.
                let _ = self.tx.send(SyncCommand::Subscribe(list_id));
                Ok(())
            }
            SyncCommand::DeleteList(list_id) => {
                self.net.delete_list(&self.token, &list_id).await?;
                Ok(())
            }
            SyncCommand::AddMember { list_id: _, body } => {
                self.net.add_member(&self.token, &body).await?;
                Ok(())
            }
            SyncCommand::RemoveMember { list_id: _, body } => {
                self.net.remove_member(&self.token, &body).await?;
                Ok(())
            }
            SyncCommand::InitialSync => self.initial_sync().await,
            SyncCommand::Pull(list_id) => self.pull(list_id).await,
            SyncCommand::Subscribe(list_id) => {
                self.subscribe(list_id);
                Ok(())
            }
        }
    }

    /// Drain the outbound queue for a list, uploading each pre-signed envelope. A
    /// row the server accepts is acked (deleted); a failed upload is released back
    /// to `pending` and the drain stops (the next Push retries).
    #[tracing::instrument(skip(self))]
    async fn push(&self, list_id: ListId) -> TodoersResult<()> {
        loop {
            let rows = self.db.take_outbound(&list_id, BATCH).await?;
            if rows.is_empty() {
                return Ok(());
            }
            for row in rows {
                let payload: UpdatePayload = postcard::from_bytes(&row.payload)?;
                let body = AppendUpdate {
                    list_id,
                    version: payload.version,
                    epoch: payload.epoch,
                    author: payload.author,
                    nonce: payload.nonce,
                    ciphertext: payload.ciphertext,
                    signature: payload.signature,
                };
                match self.net.append_update(&self.token, &body).await {
                    Ok(_) => self.db.ack_outbound(row.local_id).await?,
                    Err(e) => {
                        self.db.release_outbound(row.local_id).await?;
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Pull updates with `seq > cursor` in pages and forward each page to the store,
    /// which decrypts/merges and advances the persistent cursor.
    #[tracing::instrument(skip(self))]
    async fn pull(&self, list_id: ListId) -> TodoersResult<()> {
        let mut cursor = self.db.applied_through_seq(&list_id).await?;
        loop {
            let batch = self
                .net
                .pull_updates(&self.token, &list_id, cursor, BATCH)
                .await?;
            let n = batch.len();
            if let Some(last) = batch.last() {
                cursor = last.seq;
            }
            if !batch.is_empty() {
                let _ = self.store_tx.send(StoreCommand::ApplyRemote {
                    list_id,
                    updates: batch,
                });
            }
            if (n as i64) < BATCH {
                return Ok(());
            }
        }
    }

    /// Discover every list we belong to and bring each up to date: seed its members
    /// + key slots (so the store can decrypt), pull the log, then go live.
    #[tracing::instrument(skip(self))]
    async fn initial_sync(&self) -> TodoersResult<()> {
        let ids = self.net.fetch_lists(&self.token).await?;
        for id in ids {
            let meta = self.net.get_metadata(&self.token, &id).await?;
            let keys = self.net.get_my_keys(&self.token, &id).await?;
            let _ = self.store_tx.send(StoreCommand::IngestRemoteList {
                meta: Box::new(meta),
                keys,
            });
            let _ = self.tx.send(SyncCommand::Pull(id));
            let _ = self.tx.send(SyncCommand::Subscribe(id));
        }
        Ok(())
    }

    /// Hold a live subscription on its own task. Each frame is forwarded to the
    /// store as a one-element batch; when the socket closes (e.g. server-side lag),
    /// fall back to a pull and reconnect after a short delay.
    #[tracing::instrument(skip(self))]
    fn subscribe(&self, list_id: ListId) {
        let base = self.net.base_url.clone();
        let token = self.token.clone();
        let store_tx = self.store_tx.clone();
        let self_tx = self.tx.clone();
        tokio::spawn(async move {
            match ws::ws_subscribe(&base, &token, &list_id).await {
                Ok(stream) => {
                    futures::pin_mut!(stream);
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(dto) => {
                                let _ = store_tx.send(StoreCommand::ApplyRemote {
                                    list_id,
                                    updates: vec![dto],
                                });
                            }
                            Err(e) => {
                                warn!(error = ?e, "ws frame error; will reconcile via pull");
                                break;
                            }
                        }
                    }
                }
                Err(e) => warn!(error = ?e, "ws subscribe failed; relying on pull"),
            }
            // Socket ended: reconcile any gap, then reconnect after a beat.
            let _ = self_tx.send(SyncCommand::Pull(list_id));
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = self_tx.send(SyncCommand::Subscribe(list_id));
        });
    }
}
