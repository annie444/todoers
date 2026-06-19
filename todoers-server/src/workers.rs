use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::db::Db;

pub struct DbWorker {
    db: Db,
    interval: Duration,
    token: CancellationToken,
}

impl DbWorker {
    pub fn new(db: Db, interval: Duration, token: CancellationToken) -> Self {
        Self {
            db,
            interval,
            token,
        }
    }

    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.interval);
            loop {
                tokio::select! {
                    _ = interval.tick() => self.cleanup().await,
                    _ = self.token.cancelled() => {
                        println!("DB worker shutting down");
                        break;
                    }
                }
            }
        })
    }

    pub async fn cleanup(&self) {
        if let Err(e) = self.db.cleanup_expired_sessions().await {
            error!(?e, "failed to cleanup expired sessions");
        }
        if let Err(e) = self.db.cleanup_expired_logins().await {
            error!(?e, "failed to cleanup expired logins");
        }
    }
}
