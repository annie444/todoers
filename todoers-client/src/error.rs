//! Custom error type for the application.

pub use thiserror::Error;

pub type TodoersResult<T> = std::result::Result<T, TodoersError>;

#[derive(Error, Debug)]
pub enum TodoersError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("websocket error: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("invalid header: {0}")]
    Header(#[from] http::header::InvalidHeaderValue),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("error generating key")]
    Aead,
    #[error("device key vault error: {0}")]
    DeviceVault(std::string::String),
    #[error("API client error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("online login failed: {0}")]
    OnlineLogin(String),
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
    #[error("db error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("db initialization error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("realtime update error: {0}")]
    Loro(#[from] loro::LoroError),
    #[error("error encoding update: {0}")]
    LoroEncode(#[from] loro::LoroEncodeError),
    #[error("realtime update error: unknown id")]
    UnknownId,
    #[error("handling device identity file: {0}")]
    DeviceId(std::io::Error),
    #[error("error converting time: {0}")]
    TimeComponent(#[from] time::error::ComponentRange),
    #[error("no matching device recipient")]
    NoDevRecipient,
    #[error("bad xwing key: {0}")]
    BadXWingKey(#[from] x_wing::InvalidKey),
    #[error("error from device key store: {0}")]
    KeyStore(#[from] keyring_core::Error),
    #[error("error deriving shared key: {0}")]
    ChaCha(chacha20poly1305::Error),
    #[error("secret is not long enough: {0}")]
    Hkdf(#[from] hkdf::InvalidLength),
    #[error("error hashing password: {0}")]
    Argon2(argon2::Error),
    #[error("no password recipient found")]
    NoPassword,
    #[error("invalid database key length")]
    InvalidKeyLength,
}
