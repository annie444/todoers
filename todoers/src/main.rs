use clap::Parser;
use tokio::runtime::Builder;

mod action;
mod app;
mod auth;
mod cli;
mod components;
mod config;
mod crypto;
mod db;
mod error;
mod logging;
mod net;
mod tui;

use crate::app::App;
use crate::cli::Cli;
use crate::config::Config;
use crate::db::Db;

#[tracing::instrument]
async fn body() -> anyhow::Result<()> {
    crate::error::init()?;
    crate::logging::init()?;

    let args = Cli::parse();
    let config = Config::new()?;
    let db = Db::init(&config.config.data_dir).await?;
    let account = db.load_account().await?;
    let mut app = App::new(config, db, account, None).await?;
    app.run().await?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
        .block_on(body())
}
