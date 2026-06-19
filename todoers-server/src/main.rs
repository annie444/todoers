use anyhow::Context;
use tokio::runtime::Builder;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod crypto;
mod db;
mod error;
mod routes;
mod state;
mod workers;

use crate::state::{AppState, Hub};

async fn body() -> anyhow::Result<()> {
    let config = config::Config::load().await?;
    let pool = db::Db::init(&config.database).await?;
    let verify_signatures = config.general.verify_signatures;
    let opaque = crypto::OpaqueServer::load_or_init(&config.general.key_file).await?;

    let db_worker_token = CancellationToken::new();
    let db_worker = workers::DbWorker::new(
        pool.clone(),
        config.database.cleanup_interval,
        db_worker_token.child_token(),
    );
    let db_worker_handle = db_worker.start();

    let state = AppState {
        db: pool.clone(),
        hub: Hub::default(),
        opaque,
        verify_signatures,
    };

    let app = routes::build_router(state).await;

    let bind_addr = config.server.bind_addr();
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;
    info!(%bind_addr, verify_signatures, "todoers-server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    db_worker_token.cancel();
    if let Err(e) = db_worker_handle.await {
        warn!(?e, "DB worker task failed");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
        .block_on(body())
}

#[tracing::instrument]
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
