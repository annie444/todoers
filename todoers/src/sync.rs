//! The sync engine: the one task that talks to the server over time.
//!
//! It is deliberately key-free. The store actor ([`crate::store_worker`]) owns
//! the DEKs and Loro docs and does every crypto step; this task only moves
//! already-encrypted bytes over the wire and hands raw server DTOs back to the
//! store for keyed work. That split keeps network latency off the store actor
//! (so UI-driven edits never wait on a socket) and keeps secret material out of
//! the component that holds a bearer token.
//!
//! Flow:
//! - **Push** drains the local `outbound` queue (pre-signed envelopes) to the
//!   append endpoint, acking each row the server accepts.
//! - **Pull** walks the server log after our cursor and forwards batches to the
//!   store, which decrypts/merges and advances `applied_through_seq`.
//! - **Subscribe** holds a WebSocket for live fanout; on drop it falls back to a
//!   pull, matching the server's "laggards reconcile via pull" contract.
//! - **Control-plane** (create list, add/remove member) ships request bodies the
//!   store pre-built with sealed DEKs.

use std::time::Duration;

use futures::StreamExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{error, warn};
use uuid::Uuid;

use todoers_client::db::Db;
use todoers_client::net;
use todoers_types::{AddMemberRequest, AppendUpdate, ListId, RemoveMemberRequest, UpdatePayload};

use crate::store_worker::{CommandTx, StoreCommand};

/// How many updates to pull/push per round-trip.
const BATCH: i64 = 500;

/// What the UI / store asks the sync engine to do.
pub enum SyncCommand {
    /// Local edits for this list were enqueued — drain & upload them.
    Push(ListId),
    /// Create the list server-side under the client-minted id (local-first).
    CreateList {
        list_id: ListId,
        wrapped_dek: Vec<u8>,
    },
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

/// Run the sync engine until its command channel closes. `self_tx` lets a
/// command enqueue follow-ups (e.g. InitialSync → Pull/Subscribe per list).
pub async fn run_sync(
    base_url: String,
    token: String,
    db: Db,
    store_tx: CommandTx,
    self_tx: SyncTx,
    mut rx: SyncRx,
) {
    while let Some(cmd) = rx.recv().await {
        if let Err(e) = handle(&base_url, &token, &db, &store_tx, &self_tx, cmd).await {
            error!(error = ?e, "sync command failed");
        }
    }
}

fn uuid(list_id: ListId) -> Uuid {
    Uuid::from_bytes(list_id.0)
}

async fn handle(
    base: &str,
    token: &str,
    db: &Db,
    store_tx: &CommandTx,
    self_tx: &SyncTx,
    cmd: SyncCommand,
) -> anyhow::Result<()> {
    match cmd {
        SyncCommand::Push(list_id) => push(base, token, db, list_id).await,
        SyncCommand::CreateList {
            list_id,
            wrapped_dek,
        } => {
            net::list::create_list(base, token, uuid(list_id), &wrapped_dek).await?;
            // A freshly-created list has nothing to pull, but go live for peers.
            let _ = self_tx.send(SyncCommand::Subscribe(list_id));
            Ok(())
        }
        SyncCommand::AddMember { list_id, body } => {
            net::list::add_member(base, token, uuid(list_id), &body).await?;
            Ok(())
        }
        SyncCommand::RemoveMember { list_id, body } => {
            net::list::remove_member(base, token, uuid(list_id), &body).await?;
            Ok(())
        }
        SyncCommand::InitialSync => initial_sync(base, token, store_tx, self_tx).await,
        SyncCommand::Pull(list_id) => pull(base, token, db, store_tx, list_id).await,
        SyncCommand::Subscribe(list_id) => {
            subscribe(base, token, store_tx, self_tx, list_id);
            Ok(())
        }
    }
}

/// Drain the outbound queue for a list, uploading each pre-signed envelope. A
/// row the server accepts is acked (deleted); a failed upload is released back
/// to `pending` and the drain stops (the next Push retries).
async fn push(base: &str, token: &str, db: &Db, list_id: ListId) -> anyhow::Result<()> {
    loop {
        let rows = db.take_outbound(list_id, BATCH).await?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            let payload: UpdatePayload = serde_json::from_slice(&row.payload)?;
            let body = AppendUpdate {
                version: payload.version,
                epoch: payload.epoch,
                author: Uuid::from_bytes(payload.author.0),
                nonce: payload.nonce.to_vec(),
                ciphertext: payload.ciphertext,
                signature: payload.signature.to_vec(),
            };
            match net::updates::append_update(base, token, uuid(list_id), &body).await {
                Ok(_) => db.ack_outbound(row.local_id).await?,
                Err(e) => {
                    db.release_outbound(row.local_id).await?;
                    return Err(e.into());
                }
            }
        }
    }
}

/// Pull updates with `seq > cursor` in pages and forward each page to the store,
/// which decrypts/merges and advances the persistent cursor.
async fn pull(
    base: &str,
    token: &str,
    db: &Db,
    store_tx: &CommandTx,
    list_id: ListId,
) -> anyhow::Result<()> {
    let mut cursor = db.applied_through_seq(list_id).await?;
    loop {
        let batch = net::updates::pull_updates(base, token, uuid(list_id), cursor, BATCH).await?;
        let n = batch.len();
        if let Some(last) = batch.last() {
            cursor = last.seq;
        }
        if !batch.is_empty() {
            let _ = store_tx.send(StoreCommand::ApplyRemote {
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
async fn initial_sync(
    base: &str,
    token: &str,
    store_tx: &CommandTx,
    self_tx: &SyncTx,
) -> anyhow::Result<()> {
    let ids = net::list::fetch_lists(base, token).await?.list_ids;
    for id in ids {
        let list_id = ListId(id.into_bytes());
        let meta = net::list::get_metadata(base, token, id).await?;
        let keys = net::list::get_my_keys(base, token, id).await?;
        let _ = store_tx.send(StoreCommand::IngestRemoteList {
            meta: Box::new(meta),
            keys,
        });
        let _ = self_tx.send(SyncCommand::Pull(list_id));
        let _ = self_tx.send(SyncCommand::Subscribe(list_id));
    }
    Ok(())
}

/// Hold a live subscription on its own task. Each frame is forwarded to the
/// store as a one-element batch; when the socket closes (e.g. server-side lag),
/// fall back to a pull and reconnect after a short delay.
fn subscribe(base: &str, token: &str, store_tx: &CommandTx, self_tx: &SyncTx, list_id: ListId) {
    let base = base.to_string();
    let token = token.to_string();
    let store_tx = store_tx.clone();
    let self_tx = self_tx.clone();
    tokio::spawn(async move {
        match net::ws::ws_subscribe(&base, &token, uuid(list_id)).await {
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
