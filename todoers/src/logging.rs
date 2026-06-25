use std::sync::LazyLock;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use todoers_client::get_data_dir;

use crate::config;

pub static LOG_ENV: LazyLock<String> =
    LazyLock::new(|| format!("{}_LOG_LEVEL", config::PROJECT_NAME.clone()));
pub static LOG_FILE: LazyLock<String> = LazyLock::new(|| format!("{}.log", env!("CARGO_PKG_NAME")));

/// Initialize tracing. Returns a guard that MUST be kept alive for the lifetime
/// of the process (it flushes the non-blocking log writer on drop).
///
/// Performance: the default filter is `warn`, so `#[tracing::instrument]` spans
/// (which default to INFO) are *disabled* and cost ~nothing on hot paths. Raise
/// it per run with `RUST_LOG=...` or `TODOERS_LOG_LEVEL=...` when debugging.
/// `console_subscriber` (tokio-console) is heavy and only attaches when
/// `TODOERS_TOKIO_CONSOLE=1` is set.
pub fn init() -> anyhow::Result<WorkerGuard> {
    let directory = get_data_dir();
    std::fs::create_dir_all(directory.clone())?;
    let log_path = directory.join(LOG_FILE.clone());
    let log_file = std::fs::File::create(log_path)?;
    let (non_blocking, guard) = tracing_appender::non_blocking(log_file);

    // Default to WARN so INFO instrument spans are disabled (cheap). Honor
    // RUST_LOG, then TODOERS_LOG_LEVEL, for opt-in verbosity.
    let env_filter = EnvFilter::builder().with_default_directive(tracing::Level::WARN.into());
    let env_filter = env_filter.try_from_env().or_else(|_| {
        EnvFilter::builder()
            .with_default_directive(tracing::Level::WARN.into())
            .with_env_var(LOG_ENV.clone())
            .from_env()
    })?;

    let file_subscriber = fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_writer(non_blocking)
        .with_target(false)
        .with_ansi(false)
        .with_filter(env_filter);

    let console = if std::env::var("TODOERS_TOKIO_CONSOLE").as_deref() == Ok("1") {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        use console_subscriber::{ConsoleLayer, ServerAddr};
        Some(
            ConsoleLayer::builder()
                .with_default_env()
                .server_addr(ServerAddr::Tcp(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(127, 0, 0, 1),
                    6699,
                ))))
                .spawn(),
        )
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(file_subscriber)
        .with(ErrorLayer::default())
        .with(console)
        .try_init()?;
    Ok(guard)
}
