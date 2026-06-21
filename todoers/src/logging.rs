use std::sync::LazyLock;

use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config;

pub static LOG_ENV: LazyLock<String> =
    LazyLock::new(|| format!("{}_LOG_LEVEL", config::PROJECT_NAME.clone()));
pub static LOG_FILE: LazyLock<String> = LazyLock::new(|| format!("{}.log", env!("CARGO_PKG_NAME")));

#[tracing::instrument]
pub fn init() -> anyhow::Result<()> {
    let directory = config::get_data_dir();
    std::fs::create_dir_all(directory.clone())?;
    let log_path = directory.join(LOG_FILE.clone());
    let log_file = std::fs::File::create(log_path)?;
    let env_filter = EnvFilter::builder().with_default_directive(tracing::Level::INFO.into());
    // If the `RUST_LOG` environment variable is set, use that as the default, otherwise use the
    // value of the `LOG_ENV` environment variable. If the `LOG_ENV` environment variable contains
    // errors, then this will return an error.
    let env_filter = env_filter
        .try_from_env()
        .or_else(|_| env_filter.with_env_var(LOG_ENV.clone()).from_env())?;
    let file_subscriber = fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_writer(log_file)
        .with_target(false)
        .with_ansi(false)
        .with_filter(env_filter);
    #[cfg(not(debug_assertions))]
    tracing_subscriber::registry()
        .with(file_subscriber)
        .with(ErrorLayer::default())
        .try_init()?;
    #[cfg(debug_assertions)]
    {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        use console_subscriber::{ConsoleLayer, ServerAddr};

        let console = ConsoleLayer::builder()
            .with_default_env()
            .server_addr(ServerAddr::Tcp(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                6699,
            ))))
            .spawn();
        tracing_subscriber::registry()
            .with(file_subscriber)
            .with(ErrorLayer::default())
            .with(console)
            .try_init()?;
    }
    Ok(())
}
