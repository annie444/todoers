use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::{get_config_dir, get_data_dir};

#[derive(Parser, Debug)]
#[command(author, version = version(), about)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print the version information and license
    Version,
    /// Export the todo list to a file
    Keygen(KeygenArgs),
}

#[derive(Args, Debug)]
pub struct KeygenArgs {
    #[clap(short, long, value_name = "FILE")]
    pub output: PathBuf,
}

const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "-",
    env!("VERGEN_GIT_DESCRIBE"),
    " (",
    env!("VERGEN_BUILD_DATE"),
    ")"
);

const LICENSE_MESSAGE: &str = r#"todoers, Copyright (C) 2026 Analetta "Annie" Ehler

todoers comes with ABSOLUTELY NO WARRANTY. This is free
software, and you are welcome to redistribute it under
certain conditions."#;

#[tracing::instrument]
pub fn version() -> String {
    let author = clap::crate_authors!();

    // let current_exe_path = PathBuf::from(clap::crate_name!()).display().to_string();
    let config_dir_path = get_config_dir().display().to_string();
    let data_dir_path = get_data_dir().display().to_string();

    format!(
        "\
{VERSION_MESSAGE}

Authors: {author}

Config directory: {config_dir_path}
Data directory: {data_dir_path}

{LICENSE_MESSAGE}"
    )
}
