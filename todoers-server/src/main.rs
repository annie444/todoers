use anyhow::Context;
use tokio::runtime::Builder;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod crypto;
mod db;
mod error;
mod routes;
mod state;
mod wire;
mod workers;

use crate::state::{AppState, Hub};

async fn body() -> anyhow::Result<()> {
    let config = config::Config::load().await?;
    let pool = db::Db::init(&config.database).await?;
    let verify_signatures = config.general.verify_signatures;
    let opaque = crypto::OpaqueServer::load_or_init(&config.general.key_file).await?;

    let state = AppState {
        db: pool,
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
