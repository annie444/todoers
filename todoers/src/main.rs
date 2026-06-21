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
mod list_doc;
mod logging;
mod model;
mod net;
mod session;
mod store;
mod tui;

use crate::app::App;
use crate::cli::Cli;
use crate::config::Config;
use crate::db::Db;

#[tracing::instrument]
async fn body() -> anyhow::Result<()> {
    crate::error::init()?;
    let _log_guard = crate::logging::init()?;

    let args = Cli::parse();
    if let Some(subcommand) = args.subcommand {
        match subcommand {
            cli::Commands::Version => {
                println!("{}", cli::version());
                return Ok(());
            }
            cli::Commands::Keygen(args) => {
                crypto::keygen(&args.output)?;
                println!("Key pair generated and saved to {}", args.output.display());
                return Ok(());
            }
        }
    }
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
