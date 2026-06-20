use thiserror::Error;
use tracing::error;

pub type AppResult<T> = core::result::Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("error generating key")]
    Aead,
    #[error("signature error: {0}")]
    BadSignature(#[from] ed25519_dalek::SignatureError),
    #[error("invalid input")]
    UnknownAuthor,
    #[error("invalid input")]
    UnknownEpoch,
    #[error("invalid list")]
    WrongList,
    #[error("runtime error: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// OPAQUE registration/login protocol failure (e.g. wrong password).
    #[error("opaque protocol error")]
    Opaque(#[from] opaque_ke::errors::ProtocolError),
    /// Argon2id / key-derivation failure.
    #[error("key derivation error")]
    Kdf,
    /// AGE/SSH local-key vault failure (bad recipient/identity, decrypt failed).
    /// The message is safe to surface — it never contains secret material.
    #[error("device key vault error: {0}")]
    DeviceVault(String),
}

#[tracing::instrument]
pub fn init() -> anyhow::Result<()> {
    std::panic::set_hook(Box::new(move |panic_info| {
        if let Ok(mut t) = crate::tui::Tui::new()
            && let Err(r) = t.exit()
        {
            error!("Unable to exit Terminal: {:?}", r);
        }

        #[cfg(not(debug_assertions))]
        {
            use human_panic::{handle_dump, metadata, print_msg};
            let metadata = metadata!();
            let file_path = handle_dump(&metadata, panic_info);
            // prints human-panic message
            print_msg(file_path, &metadata)
                .expect("human-panic: printing error message to console failed");
            eprintln!("{}", panic_hook.panic_report(panic_info)); // prints color-eyre stack trace to stderr
        }

        if let Some(location) = panic_info.location() {
            error!(
                "panic occurred in file '{}' at line {}",
                location.file(),
                location.line(),
            );
        }
        if let Some(msg) = panic_info.payload_as_str() {
            error!("Error: {msg}");
        }

        #[cfg(debug_assertions)]
        {
            // Better Panic stacktrace that is only enabled when debugging.
            better_panic::Settings::auto()
                .most_recent_first(false)
                .lineno_suffix(true)
                .verbosity(better_panic::Verbosity::Full)
                .create_panic_handler()(panic_info);
        }

        std::process::exit(1);
    }));
    Ok(())
}

/// Similar to the `std::dbg!` macro, but generates `tracing` events rather
/// than printing to stdout.
///
/// By default, the verbosity level for the generated events is `DEBUG`, but
/// this can be customized.
#[macro_export]
macro_rules! trace_dbg {
        (target: $target:expr, level: $level:expr, $ex:expr) => {
            {
                match $ex {
                        value => {
                                tracing::event!(target: $target, $level, ?value, stringify!($ex));
                                value
                        }
                }
            }
        };
        (level: $level:expr, $ex:expr) => {
                trace_dbg!(target: module_path!(), level: $level, $ex)
        };
        (target: $target:expr, $ex:expr) => {
                trace_dbg!(target: $target, level: tracing::Level::DEBUG, $ex)
        };
        ($ex:expr) => {
                trace_dbg!(level: tracing::Level::DEBUG, $ex)
        };
}
