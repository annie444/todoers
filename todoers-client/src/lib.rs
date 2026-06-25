pub mod auth;
pub mod crypto;
pub mod db;
pub mod device_key;
pub mod error;
pub mod list_doc;
pub mod model;
pub mod net;
pub mod session;
pub mod sqlcipher;

use std::env;
use std::path::PathBuf;
use std::sync::LazyLock;

use directories::{BaseDirs, ProjectDirs, UserDirs};

pub static DATA_FOLDER: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| env::var("TODOERS_DATA").ok().map(PathBuf::from));

#[tracing::instrument]
pub fn get_data_dir() -> PathBuf {
    if let Some(s) = DATA_FOLDER.clone() {
        s
    } else if let Some(user) =
        UserDirs::new().map(|u| u.home_dir().join(".local").join("state").join("todoers"))
        && user.exists()
    {
        user
    } else if let Some(base) = BaseDirs::new().and_then(|b| b.state_dir().map(|s| s.to_path_buf()))
        && base.exists()
    {
        base
    } else if let Some(proj_dirs) = project_dir() {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    }
}

#[tracing::instrument]
fn project_dir() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", "todoers")
}
