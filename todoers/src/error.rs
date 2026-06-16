use thiserror::Error;

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
}
