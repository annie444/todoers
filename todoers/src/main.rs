use std::sync::Arc;

use clap::Parser;
use dialoguer::{Confirm, Password};
use tokio::runtime::Builder;

use todoers_client::crypto;
use todoers_client::db::Db;
use todoers_client::sqlcipher;

mod action;
mod app;
mod cli;
mod components;
mod config;
mod error;
mod logging;
mod prompt;
mod tui;
mod view;

use crate::app::App;
use crate::cli::{Cli, Commands, LOGO};
use crate::config::Config;

const KEY_CONTENTS: &str = r##"# This is your device vault key. Keep it secret and safe!
# It protects the cached keys that unlock your todo lists on this device.
# Anyone with access to this file can impersonate you on this device."##;

#[tracing::instrument]
async fn body() -> anyhow::Result<()> {
    error::init()?;
    let _log_guard = logging::init()?;

    let args = Cli::parse();
    if let Some(subcommand) = args.subcommand {
        match subcommand {
            Commands::Version => {
                println!("{}", cli::version());
                return Ok(());
            }
            Commands::Keygen(args) => {
                let public_key = crypto::keygen(&args.output, Some(KEY_CONTENTS))?;
                println!(
                    "Device vault key generated and saved to {}.",
                    args.output.display()
                );
                println!(
                    r#"Public key:

{public_key}

Save this public key in your configuration as:

    [device_unlock]
    enabled = true
    recipient = "<your-public-key>"

"#
                );
                return Ok(());
            }
        }
    }
    let config = Config::new()?;

    // Unlock (or, on first run, create) the database encryption key before
    // opening the encrypted store. The device key store auto-unlocks on every
    // subsequent run; the recovery key is the fallback if that device key is lost.
    let envelope_path = todoers_client::get_data_dir().join("db_keys.json");
    let (envelope, recovery) = sqlcipher::load_or_create_envelope(&envelope_path).await?;
    let key = match sqlcipher::unlock_with_device(&envelope).await {
        Ok(key) => key,
        Err(e) => {
            tracing::warn!("device unlock failed ({e}); falling back to recovery key");
            prompt_recovery_key(&envelope).await?
        }
    };

    let db = Arc::new(Db::init(&config.config.data_dir, &key, envelope.cipher).await?);
    if let Some(recovery) = recovery {
        show_recovery_key(&recovery)?;
    }

    let account = db.load_account().await?;
    let mut app = App::new(config, db, account, None).await?;
    app.run().await?;

    Ok(())
}

/// Read the recovery key from the terminal and unlock the database key envelope.
/// Retries a few times, then gives up — without a valid key the data is
/// unrecoverable, by design.
async fn prompt_recovery_key(envelope: &sqlcipher::TodoersKeyEnvelope) -> anyhow::Result<[u8; 32]> {
    const MAX_ATTEMPTS: u32 = 5;

    eprintln!(
        r#"
This device's key could not unlock your encrypted database.
Enter your recovery key to continue (dashes, spaces, and case are ignored)."#
    );

    for attempt in 1..=MAX_ATTEMPTS {
        let mismatch_err = if attempt < MAX_ATTEMPTS {
            "Keys don't match, try again."
        } else {
            "Out of attempts, giving up."
        };
        let recovery_key = Password::new()
            .with_prompt("Recovery key")
            .with_confirmation("Re-enter key", mismatch_err)
            .report(true)
            .allow_empty_password(false)
            .interact()?;

        let typed = sqlcipher::canonical(&recovery_key);
        if typed.is_empty() {
            anyhow::bail!("No recovery key entered");
        }

        match sqlcipher::unlock_with_password(envelope, &typed).await {
            Ok(key) => return Ok(key),
            Err(_) => {
                eprintln!(
                    "That recovery key did not work (attempt {attempt} of {MAX_ATTEMPTS}). Try again."
                )
            }
        }
    }
    anyhow::bail!("Could not unlock the database with the recovery key")
}

/// Print a freshly generated recovery key once (first run only) and wait for the
/// user to acknowledge that they have saved it.
fn show_recovery_key(recovery: &str) -> anyhow::Result<()> {
    println!(
        r#"
========================  RECOVERY KEY  ========================

{recovery}

Write this down and store it somewhere safe. It is the ONLY way to
recover your data if this device's key is lost, and it will not be
shown again.
===============================================================
"#
    );

    let confirmation = Confirm::new()
        .with_prompt("Have you saved your recovery key in a safe place?")
        .report(true)
        .show_default(true)
        .wait_for_newline(true)
        .default(true)
        .interact()?;

    if confirmation {
        println!("{LOGO}");
    } else {
        anyhow::bail!("Recovery key not confirmed; exiting.");
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
        .block_on(body())
}
