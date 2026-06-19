use std::sync::Arc;

use axum::extract::ws::Message;
use dashmap::DashMap;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::crypto::OpaqueServer;
use crate::db::Db;

/// Shared application state. `Clone` is cheap: `PgPool` is internally `Arc`,
/// and `Hub` wraps an `Arc<DashMap>`.
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Db,
    pub hub: Hub,
    pub opaque: OpaqueServer,
    /// When true, the server verifies each update's Ed25519 signature before
    /// storing it — the one piece of "understanding" a blind relay is allowed.
    pub verify_signatures: bool,
}

/// Per-list real-time fanout. One `broadcast` channel per list; ≤6 subscribers
/// each, low volume, so this is deliberately simple — no external broker.
#[derive(Debug, Clone, Default)]
pub struct Hub {
    channels: Arc<DashMap<Uuid, broadcast::Sender<Message>>>,
}

impl Hub {
    /// Capacity of each list's broadcast ring buffer. A slow client that lags
    /// past this gets a `RecvError::Lagged` and reconnects to catch up via the
    /// pull endpoint — exactly the snapshot-then-tail path the client already has.
    const CHANNEL_CAPACITY: usize = 256;

    /// Get (or lazily create) the sender for a list, so subscribers can attach.
    pub fn sender(&self, list_id: Uuid) -> broadcast::Sender<Message> {
        self.channels
            .entry(list_id)
            .or_insert_with(|| broadcast::channel(Self::CHANNEL_CAPACITY).0)
            .clone()
    }

    /// Publish a message to any online subscribers of a list. No-op if nobody
    /// is currently listening (no channel materialized yet).
    pub fn publish(&self, list_id: Uuid, msg: Message) {
        if let Some(tx) = self.channels.get(&list_id) {
            // Err only means "no receivers"; that's fine, offline members catch
            // up via pull on next connect.
            let _ = tx.send(msg);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl AppState {
        pub fn new_for_test(db: sqlx::PgPool) -> Self {
            Self {
                db: crate::db::Db::new_for_test(db),
                hub: Hub::default(),
                opaque: OpaqueServer::new_for_test(),
                verify_signatures: true,
            }
        }
    }
}
