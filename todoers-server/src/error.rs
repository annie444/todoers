use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tracing::error;

/// Unified server error. Everything a handler can fail with maps to one HTTP
/// status here. Database internals are never leaked to the client.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    /// The update's Ed25519 signature did not verify against the author's
    /// known signing key (also implies non-membership when verification is on).
    #[error("invalid signature")]
    InvalidSignature,

    #[error(transparent)]
    Db(#[from] sqlx::Error),

    #[error("task join error: {0}")]
    TokioTaskJoin(#[from] tokio::task::JoinError),

    #[error("bad cryptographic material: {0}")]
    Opaque(#[from] opaque_ke::errors::ProtocolError),

    #[error("bad encoding: {0}")]
    Base46(#[from] base64::DecodeError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(e) => {
                error!(error = %e, "bad request");
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::InvalidSignature => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Opaque(e) => {
                error!(error = %e, "cryptographic protocol error");
                (
                    StatusCode::BAD_REQUEST,
                    "bad cryptographic material".to_string(),
                )
            }
            AppError::Db(e) => {
                // Log the real error; return an opaque message.
                error!(error = %e, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
            AppError::TokioTaskJoin(e) => {
                error!(error = %e, "task join error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
            AppError::Base46(e) => {
                error!(error = %e, "base64 decoding error");
                (StatusCode::BAD_REQUEST, "bad encoding".to_string())
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
