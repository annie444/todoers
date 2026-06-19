use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use config::Config as ConfigBuilder;
use directories::{BaseDirs, ProjectDirs};
use serde::{Deserialize, Serialize};

static BASE_DIRS: LazyLock<Option<BaseDirs>> = LazyLock::new(BaseDirs::new);
static PROJ_DIRS: LazyLock<Option<ProjectDirs>> = LazyLock::new(|| {
    ProjectDirs::from("com", "annieehler", "todoers-server")
        .or_else(|| ProjectDirs::from("", "", "todoers-server"))
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub database: DbConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub general: GeneralConfig,
}

impl Config {
    pub async fn load() -> anyhow::Result<Self> {
        let mut config = ConfigBuilder::builder()
            .add_source(config::File::with_name("todoers").required(false))
            .add_source(config::File::with_name("todoers-server/todoers").required(false))
            .add_source(config::Environment::with_prefix("TODOERS").separator("__"));
        #[cfg(unix)]
        {
            config = config
                .add_source(config::File::with_name("/etc/todoers").required(false))
                .add_source(config::File::with_name("/etc/todoers/todoers").required(false));
        }
        if let Some(base_dirs) = BASE_DIRS.as_ref() {
            config = config.add_source(
                config::File::with_name(&format!("{}/todoers", base_dirs.config_dir().display()))
                    .required(false),
            )
        }
        if let Some(project_dirs) = PROJ_DIRS.as_ref() {
            config = config.add_source(
                config::File::with_name(&format!(
                    "{}/todoers",
                    project_dirs.config_dir().display()
                ))
                .required(false),
            )
        }
        Ok(config.build()?.try_deserialize()?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default = "DbConfig::default_database")]
    pub database: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
    #[serde(
        with = "humantime_serde",
        default = "DbConfig::default_cleanup_interval"
    )]
    pub cleanup_interval: Duration,
}

impl DbConfig {
    pub fn default_database() -> String {
        "postgres".into()
    }

    pub fn default_cleanup_interval() -> Duration {
        Duration::from_hours(1)
    }
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            host: None,
            port: None,
            database: Self::default_database(),
            username: None,
            password: None,
            ca_path: None,
            cert_path: None,
            key_path: None,
            cleanup_interval: Self::default_cleanup_interval(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "ServerConfig::default_address")]
    pub address: String,
    #[serde(default = "ServerConfig::default_port")]
    pub port: u16,
}

impl ServerConfig {
    pub fn default_address() -> String {
        "127.0.0.1".into()
    }

    pub fn default_port() -> u16 {
        8192
    }

    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: Self::default_address(),
            port: Self::default_port(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "GeneralConfig::default_verify_signatures")]
    pub verify_signatures: bool,
    #[serde(default = "GeneralConfig::default_key_file")]
    pub key_file: PathBuf,
}

impl GeneralConfig {
    pub fn default_verify_signatures() -> bool {
        true
    }
    pub fn default_key_file() -> PathBuf {
        if let Some(project_dirs) = PROJ_DIRS.as_ref() {
            project_dirs.data_dir().join("server_state.bin")
        } else if let Some(base_dirs) = BASE_DIRS.as_ref() {
            base_dirs
                .data_dir()
                .join("todoers")
                .join("server_state.bin")
        } else {
            PathBuf::from("server_state.bin")
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            verify_signatures: Self::default_verify_signatures(),
            key_file: Self::default_key_file(),
        }
    }
}
